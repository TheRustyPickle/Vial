use anyhow::{Context as _, Result, anyhow};
use gpui::prelude::FluentBuilder;
use gpui::*;
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::group_box::{GroupBox, GroupBoxVariants};
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::notification::Notification;
use gpui_component::scroll::ScrollableElement;
use gpui_component::{Disableable, StyledExt, WindowExt};
use gpui_component::{IconName, h_flex, v_flex};
use rfd::FileDialog;
use std::env::set_current_dir;
use std::path::PathBuf;
use vial_shared::config::Config;
use vial_shared::{FullSecret, SecretFile};

use crate::crypto::{Commons, ToDecrypt};
use crate::utils::byte_size_to_readable;

pub struct ReceiveView {
    config: Config,
    url_state: Entity<InputState>,
    key_state: Entity<InputState>,
    // (id, key)
    decrypt_key: Entity<Option<(String, String)>>,
    decrypted_state: Option<FullSecret>,
    loading: bool,
    decrypt_text: Entity<InputState>,
    download_path: Option<PathBuf>,
}

impl ReceiveView {
    pub fn new(config: Config, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let url_state = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Enter a secret URL")
                .multi_line(false)
        });

        let key_state = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Enter a decryption key")
                .masked(true)
                .multi_line(false)
        });

        let decrypt_key = cx.new(|_| None);

        cx.observe_in(&decrypt_key, window, |this, state, window, cx| {
            let value = state.read(cx);

            if value.is_some() {
                this.loading = true;
                this.start_decrypt(window, cx);
            }
        })
        .detach();

        let decrypt_text = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .soft_wrap(true)
                .auto_grow(7, 7)
        });

        cx.subscribe_in(&decrypt_text, window, {
            move |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::Change = ev {
                    this.sync_decrypt_text(window, cx);
                    cx.notify();
                }
            }
        })
        .detach();

        Self {
            config,
            url_state,
            key_state,
            decrypt_key,
            decrypted_state: None,
            loading: false,
            decrypt_text,
            download_path: None,
        }
    }

    fn sync_decrypt_text(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let current_state = self.decrypt_text.read(cx).value();

        let Some(secret) = &self.decrypted_state else {
            return;
        };

        let text = secret.text.to_string();

        if text == current_state.as_str() {
            return;
        }

        self.decrypt_text.update(cx, |state, cx| {
            state.set_value(text, window, cx);
        });
    }

    fn paste_content(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        let Some(value) = cx.read_from_clipboard() else {
            return;
        };

        let Some(first_entry) = value.entries().first() else {
            return;
        };

        if let ClipboardEntry::String(text) = first_entry {
            self.url_state.update(cx, |state, cx| {
                let trimmed = text.text().replace('\n', "");
                state.set_value(trimmed.clone(), window, cx);
            });
        }
    }

    fn clear_url(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.url_state.update(cx, |state, cx| {
            state.set_value(String::new(), window, cx);
        });
    }

    fn submit(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        let source = self.url_state.read(cx).value();

        let mut show_error = || {
            let notification =
                Notification::error("Could not find a secret ID from the given URL".to_string())
                    .title("No secret ID found");
            window.push_notification(notification, cx);
        };

        let Some(secret_id) = source.split('/').next_back() else {
            show_error();
            return;
        };

        if secret_id.is_empty() || secret_id.contains(' ') {
            show_error();
            return;
        }

        let key = secret_id.split_once('#');

        if let Some((id, key)) = key {
            self.decrypt_key.update(cx, |state, cx| {
                *state = Some((id.to_string(), key.to_string()));
                cx.notify();
            });
        } else {
            let input = self.key_state.clone();
            let decrypt_key = self.decrypt_key.clone();
            let id = secret_id.to_string();

            window.open_dialog(cx, move |dialog, _, _| {
                let input = input.clone();
                let decrypt_key = decrypt_key.clone();
                let id = id.clone();
                dialog
                    .title("Decrypt Key/Password")
                    .child(v_flex().gap_3().child(Input::new(&input).mask_toggle()))
                    .footer(move |_, _, _, _| {
                        let input = input.clone();
                        let input_clone = input.clone();
                        let decrypt_key = decrypt_key.clone();
                        let id = id.clone();
                        vec![
                            Button::new("ok").primary().label("Submit").on_click(
                                move |_, window, cx| {
                                    let input_value = input_clone.read(cx).value();
                                    decrypt_key.update(cx, |state, cx| {
                                        *state = Some((id.clone(), input_value.to_string()));
                                        cx.notify();
                                    });
                                    input_clone.update(cx, |state, cx| {
                                        state.set_value(String::new(), window, cx);
                                    });
                                    window.close_dialog(cx);
                                },
                            ),
                            Button::new("cancel")
                                .label("Cancel")
                                .on_click(move |_, window, cx| {
                                    input.update(cx, |state, cx| {
                                        state.set_value(String::new(), window, cx);
                                    });

                                    window.close_dialog(cx);
                                }),
                        ]
                    })
            });
        }
    }

    fn start_decrypt(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let decrypt_key = self.decrypt_key.read(cx);
        let Some((id, key)) = decrypt_key else {
            self.loading = false;
            return;
        };

        let id = id.clone();
        let key = key.clone();

        self.loading = true;

        let params = Commons {
            server_url: self.config.get_server_url(),
            web_ui_url: self.config.get_web_ui_url(),
            schema: None,
        };

        let decrypt_task =
            cx.background_spawn(async move { ToDecrypt::new(id, key, params).decrypt_secret() });

        cx.spawn_in(window, async |this, cx| {
            let result = decrypt_task.await;

            if let Err(e) = result {
                if let Err(e) = cx.window_handle().update(cx, |_, window, cx| {
                    let notification =
                        Notification::error(format!("Error: {e:#}")).title("Decryption Failed");
                    window.push_notification(notification, cx);

                    if let Err(e) = this.update(cx, |this, cx| {
                        this.loading = false;

                        cx.notify();
                    }) {
                        println!("Error while updating: {e}");
                    }
                }) {
                    println!("Failed to create notification. Error: {e}");
                }

                return;
            }

            if let Err(e) = cx.window_handle().update(cx, |_, window, cx| {
                if let Err(e) = this.update(cx, |this, cx| {
                    this.decrypted_state = Some(result.unwrap());
                    this.loading = false;
                    this.url_state.update(cx, |state, cx| {
                        state.set_value(String::new(), window, cx);
                    });

                    cx.notify();
                }) {
                    println!("Error while updating: {e}");
                }
            }) {
                println!("Error while updating: {e}");
            }
        })
        .detach();
    }

    fn decrypt_url_input(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let input_value = self.url_state.read(cx).value();
        let input = Input::new(&self.url_state).w_full();

        if input_value.is_empty() {
            input
        } else {
            input.suffix(
                Button::new("clear")
                    .ghost()
                    .w_5()
                    .h_5()
                    .icon(IconName::CircleX)
                    .on_click(cx.listener(Self::clear_url)),
            )
        }
    }

    fn copy_content(&mut self, _: &ClickEvent, _window: &mut Window, cx: &mut Context<Self>) {
        let Some(secret) = &self.decrypted_state else {
            return;
        };

        let clipboard_item = ClipboardItem::new_string(secret.text.to_string());
        cx.write_to_clipboard(clipboard_item);
    }

    fn download_file(&mut self, index: usize, window: &mut Window, cx: &mut Context<Self>) {
        self.set_download_path();

        let Some(secret) = &self.decrypted_state else {
            return;
        };

        let Some(file) = secret.files.get(index) else {
            return;
        };

        let result = self.save_file(file);

        if let Err(e) = result {
            let notification = Notification::error(format!("Failed to save file: {e:#}"))
                .title("Error saving file");
            window.push_notification(notification, cx);
        } else {
            let notification = Notification::success("File saved successfully");
            window.push_notification(notification, cx);
        }
    }

    fn download_all(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.set_download_path();

        let Some(secret) = &self.decrypted_state else {
            return;
        };

        for file in &secret.files {
            let result = self.save_file(file);

            if let Err(e) = result {
                let notification = Notification::error(format!("Failed to save file: {e:#}"))
                    .title("Error saving file");
                window.push_notification(notification, cx);
            }
        }

        let notification = Notification::success("Files saved successfully");
        window.push_notification(notification, cx);
    }

    fn save_file(&self, file: &SecretFile) -> Result<()> {
        let Some(path) = &self.download_path else {
            return Err(anyhow!("No download path set"));
        };

        set_current_dir(path)
            .with_context(|| format!("Failed to change directory to {}", path.display()))?;

        let path = std::path::Path::new(file.filename());

        // If path exists, try to save the file by adding (x) number, at most 10 times.

        let mut saved = false;

        if path.exists() {
            for i in 0..10 {
                let new_file_name = format!("{} ({})", file.filename(), i + 1);
                let new_path = std::path::Path::new(&new_file_name);

                if !new_path.exists() {
                    file.write(new_path).map_err(|e| {
                        anyhow!("Failed to save file at path {}: {e}", new_path.display())
                    })?;

                    saved = true;
                    break;
                }
            }
        } else {
            file.write(path)
                .map_err(|e| anyhow!("Failed to save file at path {}: {e}", path.display()))?;
            saved = true;
        }

        if !saved {
            return Err(anyhow!(
                "Failed to save file, likely the name already exists"
            ));
        }

        Ok(())
    }

    fn set_download_path(&mut self) {
        if self.download_path.is_some() {
            return;
        }

        let Some(config_path) = &self.config.download_path else {
            let Some(folder) = FileDialog::new().pick_folder() else {
                return;
            };

            self.download_path = Some(folder);
            return;
        };

        self.download_path = Some(config_path.clone());
    }

    fn close(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.decrypted_state = None;
        self.decrypt_text
            .update(cx, |this, cx| this.set_value(String::new(), window, cx));
        self.decrypt_key.update(cx, |this, _| *this = None);
        self.url_state
            .update(cx, |this, cx| this.set_value(String::new(), window, cx));
    }

    pub fn update_config(&mut self, config: &Config) {
        self.config = config.clone();
    }
}

impl Render for ReceiveView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.sync_decrypt_text(window, cx);

        v_flex()
            .gap_2()
            .h_full()
            .when(self.decrypted_state.is_some(), |d| {
                let secret = self.decrypted_state.as_ref().unwrap();
                let file_count = secret.total_files();

                d.v_flex()
                    .gap_6()
                    .h_full()
                    .child(
                        v_flex()
                            .gap_2()
                            .child(
                                h_flex()
                                    .justify_between()
                                    .items_center()
                                    .child(div().text_lg().font_semibold().child("Secret Text"))
                                    .child(
                                        Button::new("copy")
                                            .label("Copy")
                                            .on_click(cx.listener(Self::copy_content)),
                                    ),
                            )
                            .child(Input::new(&self.decrypt_text).h_40()),
                    )
                    .when(file_count > 0, |d| {
                        d.v_flex()
                            .gap_3()
                            .child(
                                h_flex()
                                    .justify_between()
                                    .items_center()
                                    .child(
                                        div()
                                            .text_lg()
                                            .font_semibold()
                                            .child(format!("Files ({file_count})")),
                                    )
                                    .child(
                                        Button::new("download_all")
                                            .label("Download all")
                                            .primary()
                                            .on_click(cx.listener(Self::download_all)),
                                    ),
                            )
                            .child(
                                GroupBox::new().outline().child(
                                    v_flex()
                                        .max_h_40()
                                        .id("files")
                                        .overflow_y_scrollbar()
                                        .children(secret.files.iter().enumerate().map(
                                            |(idx, file)| {
                                                let filename = file.filename.clone();
                                                let size = byte_size_to_readable(
                                                    file.content.len() as f64,
                                                );

                                                h_flex()
                                                    .justify_between()
                                                    .items_center()
                                                    .py_2()
                                                    .pr_6()
                                                    .pl_4()
                                                    .child(
                                                        h_flex()
                                                            .gap_2()
                                                            .child(
                                                                div()
                                                                    .font_medium()
                                                                    .child(filename.clone()),
                                                            )
                                                            .child(
                                                                div()
                                                                    .text_sm()
                                                                    .child(format!("({size})")),
                                                            ),
                                                    )
                                                    .child(
                                                        Button::new(SharedString::new(format!(
                                                            "download_{idx}"
                                                        )))
                                                        .icon(IconName::ArrowDown)
                                                        .on_click(cx.listener(
                                                            move |this, _, window, cx| {
                                                                this.download_file(idx, window, cx);
                                                            },
                                                        )),
                                                    )
                                            },
                                        )),
                                ),
                            )
                    })
                    .child(
                        h_flex().w_full().justify_center().items_center().child(
                            Button::new("close")
                                .label("Close")
                                .primary()
                                .w_2_5()
                                .on_click(cx.listener(Self::close)),
                        ),
                    )
            })
            .when(self.decrypted_state.is_none(), |d| {
                d.size_full().child(
                    v_flex()
                        .size_full()
                        .gap_4()
                        .items_center()
                        .justify_center()
                        .child(
                            h_flex()
                                .w_full()
                                .gap_2()
                                .child(self.decrypt_url_input(cx))
                                .child(
                                    Button::new("paste")
                                        .label("Paste")
                                        .outline()
                                        .on_click(cx.listener(Self::paste_content)),
                                ),
                        )
                        .child(
                            Button::new("decrypt")
                                .label("Submit")
                                .primary()
                                .loading(self.loading)
                                .disabled(self.loading)
                                .w_2_5()
                                .on_click(cx.listener(Self::submit)),
                        ),
                )
            })
    }
}
