use gpui::*;
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::clipboard::Clipboard;
use gpui_component::group_box::{GroupBox, GroupBoxVariants};
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::label::Label;
use gpui_component::progress::Progress;
use gpui_component::radio::{Radio, RadioGroup};
use gpui_component::scroll::ScrollableElement;
use gpui_component::tooltip::Tooltip;
use gpui_component::{ActiveTheme as _, Disableable, PixelsExt, Root, StyledExt, WindowExt};
use gpui_component::{IconName, h_flex, v_flex};
use rfd::FileDialog;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;
use vial_shared::config::Config;

use crate::crypto::{DEFAULT_SERVER_URL, MAX_SIZE, Schema, ToEncrypt};

#[derive(Clone)]
pub struct SendView {
    config: Config,
    to_encrypt: Entity<InputState>,
    secret_url_state: Entity<InputState>,
    secret_url: String,
    files: BTreeSet<PathBuf>,
    full_size: u64,
    file_size: u64,
    progress: f32,
    loading: bool,
    schema_index: usize,
    password_entity: Entity<InputState>,
    password: Entity<Option<String>>,
}

impl SendView {
    pub fn new(config: Config, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let to_encrypt = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .auto_grow(7, 7)
                .placeholder("Enter text to encrypt")
                .searchable(true)
                .soft_wrap(true)
        });

        let secret_url_state = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Encrypt something to get a link!")
                .multi_line(false)
        });

        let password_state = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Enter a password to encrypt with")
                .multi_line(false)
                .masked(true)
        });

        let password = cx.new(|_| None);

        cx.observe(&password, |this, state, cx| {
            let value = state.read(cx);

            if value.is_some() {
                this.loading = true;
                this.start_encryption(cx);
            }
        })
        .detach();

        cx.subscribe_in(&to_encrypt, window, {
            move |this, _, ev: &InputEvent, _window, cx| {
                if let InputEvent::Change = ev {
                    this.update_progress(cx);

                    cx.notify()
                }
            }
        })
        .detach();

        cx.subscribe_in(&secret_url_state, window, {
            move |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::Change = ev {
                    this.reset_secret_url(window, cx);
                    cx.notify()
                }
            }
        })
        .detach();

        Self {
            config,
            to_encrypt,
            secret_url: String::new(),
            secret_url_state,
            files: BTreeSet::new(),
            file_size: 0,
            full_size: 0,
            progress: 0.0,
            loading: false,
            schema_index: 0,
            password_entity: password_state,
            password,
        }
    }

    fn reset_secret_url(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let current_state = self.secret_url_state.read(cx).value();

        if current_state == self.secret_url {
            return;
        }

        self.secret_url_state.update(cx, |state, cx| {
            state.set_value(self.secret_url.clone(), window, cx);
        });
    }

    fn update_progress(&mut self, cx: &mut Context<Self>) {
        let total_size_text = self.to_encrypt.read(cx).value().len() as u64;
        let total_size_files: u64 = self.files.iter().map(|f| f.metadata().unwrap().len()).sum();

        self.full_size = total_size_text + total_size_files;

        self.file_size = total_size_files;

        let progress = self.full_size as f32 / MAX_SIZE as f32;

        self.progress = progress * 100.0;
    }

    fn submit(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        let schema = Schema::from_index(self.schema_index);

        if let Schema::Password = schema
            && self.password.read(cx).is_none()
        {
            let input = self.password_entity.clone();
            let password = self.password.clone();

            window.open_dialog(cx, move |dialog, _, _| {
                let input = input.clone();
                let password = password.clone();
                dialog
                    .title("Encrypt Password")
                    .child(v_flex().gap_3().child(Input::new(&input).mask_toggle()))
                    .footer(move |_, _, _, _| {
                        let input = input.clone();
                        let password = password.clone();
                        vec![
                            Button::new("ok").primary().label("Submit").on_click(
                                move |_, window, cx| {
                                    password.update(cx, |state, cx| {
                                        *state = Some("String".to_string());
                                        cx.notify()
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
        } else {
            self.start_encryption(cx);
        }
    }

    fn start_encryption(&mut self, cx: &mut Context<Self>) {
        let text = self.to_encrypt.read(cx).value().to_string();
        let files = self.files.clone();
        let schema = Schema::from_index(self.schema_index);

        let encrypt_task = cx.background_spawn(async move {
            ToEncrypt::new(text, files, schema, None).create_secret()
        });

        cx.spawn(async |this, cx| {
            let result = encrypt_task.await;

            let result = this.update(cx, |this, cx| {
                this.secret_url = result.unwrap();
                this.loading = false;
                cx.notify();
            });

            if let Err(err) = result {
                println!("Error: {}", err);
            }
        })
        .detach();
    }

    fn get_files(&mut self, _: &ClickEvent, _window: &mut Window, cx: &mut Context<Self>) {
        let Some(files) = FileDialog::new().pick_files() else {
            return;
        };

        self.files.extend(files);

        self.update_progress(cx);
    }

    fn show_files_title(&mut self) -> impl IntoElement {
        let files_count = self.files.len();

        if files_count == 0 {
            div().child(Label::new("No files selected"))
        } else {
            div().child(Label::new(format!("Files: {}", files_count)))
        }
    }

    fn show_files(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        if self.files.is_empty() {
            return div();
        }

        v_flex().children(self.files.iter().enumerate().map(|(ix, path)| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "Unknown file".into());

            let size_kb = path.metadata().map(|m| m.len()).unwrap_or(0) / 1024;

            let path = path.clone();

            h_flex()
                .items_center()
                .gap_2()
                .rounded_md()
                .px_4()
                .child(div().flex_1().truncate().child(Label::new(name)))
                .child(
                    div()
                        .w_16()
                        .text_align(TextAlign::Right)
                        .child(Label::new(format!("{size_kb} KB"))),
                )
                .child(
                    Button::new(SharedString::new(format!("remove-button-{ix}")))
                        .icon(IconName::CircleX)
                        .ghost()
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.files.remove(&path);
                            this.update_progress(cx);
                        })),
                )
        }))
    }

    fn show_url_input(&mut self, window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let window_size = window.viewport_size().width;

        let url_state = self.secret_url_state.clone();

        let url = self.secret_url.clone();

        if self.secret_url.is_empty() {
            return div().into_any_element();
        }

        v_flex()
            .w_full()
            .items_center()
            .h_full()
            .justify_end()
            .pb_10()
            .pt_5()
            .with_animation(
                "url_input",
                Animation::new(Duration::from_millis(1000)).with_easing(ease_out_quint()),
                move |this_div, value| {
                    let target_w = window_size.as_f32();
                    let current_w = value * target_w;

                    this_div
                        .w_full()
                        .items_center()
                        .h_full()
                        .justify_end()
                        .child(
                            v_flex().w(px(current_w)).max_w_full().child(
                                Input::new(&url_state)
                                    .border_2()
                                    .rounded_lg()
                                    .suffix(Clipboard::new("clipboard").value(url.clone())),
                            ),
                        )
                },
            )
            .into_any_element()
    }

    fn show_schema_choice(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let random_radio =
            Radio::new("random")
                .label("Use Random key schema")
                .tooltip(|window, cx| {
                    Tooltip::new("Generate a random key and encrypt the content with it")
                        .build(window, cx)
                });

        let password_radio =
            Radio::new("password")
                .label("Use Password schema")
                .tooltip(|window, cx| {
                    Tooltip::new("Encrypt the content with a password input given by the user")
                        .build(window, cx)
                });

        RadioGroup::horizontal("options")
            .children([random_radio, password_radio])
            .selected_index(Some(self.schema_index))
            .on_click(cx.listener(|view, selected_index: &usize, _, cx| {
                view.schema_index = *selected_index;
                cx.notify();
            }))
    }

    fn max_size(&self) -> usize {
        if let Some(max_size) = self.config.max_size
            && let Some(url) = &self.config.server_url
            && url != DEFAULT_SERVER_URL
        {
            max_size
        } else {
            MAX_SIZE
        }
    }
}

impl Render for SendView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let dialog_layer = Root::render_dialog_layer(window, cx);
        self.reset_secret_url(window, cx);

        v_flex()
            .gap_2()
            .h_full()
            .child(
                Input::new(&self.to_encrypt)
                    .border_2()
                    .rounded_lg()
                    .border_color(cx.theme().border),
            )
            .child(
                GroupBox::new().outline().child(
                    v_flex()
                        .gap_2()
                        .child(
                            h_flex()
                                .justify_between()
                                .items_center()
                                .child(self.show_files_title())
                                .child(
                                    Button::new("add-files")
                                        .icon(IconName::Plus)
                                        .label("Add Files")
                                        .outline()
                                        .on_click(cx.listener(Self::get_files)),
                                ),
                        )
                        .child(
                            v_flex()
                                .id("Files")
                                .max_h_40()
                                .overflow_y_scrollbar()
                                .child(self.show_files(cx)),
                        ),
                ),
            )
            .child(
                v_flex()
                    .justify_center()
                    .items_center()
                    .gap_2()
                    .child(Progress::new().value(self.progress).h_4().rounded_lg())
                    .child(
                        Label::new(format!(
                            "{:.2} MB of {:.2} MB used",
                            self.full_size as f64 / (1024 * 1024) as f64,
                            self.max_size() as f64 / (1024 * 1024) as f64
                        ))
                        .font_semibold(),
                    ),
            )
            .child(div().child(self.show_schema_choice(window, cx)))
            .child(
                h_flex().justify_center().items_center().pt_10().child(
                    Button::new("Submit")
                        .label("Submit")
                        .disabled(self.full_size == 0 || self.full_size > self.max_size() as u64)
                        .primary()
                        .loading(self.loading)
                        .w_2_5()
                        .on_click(cx.listener(Self::submit)),
                ),
            )
            .child(self.show_url_input(window, cx))
            .children(dialog_layer)
    }
}
