use gpui::*;
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::clipboard::Clipboard;
use gpui_component::group_box::{GroupBox, GroupBoxVariants};
use gpui_component::input::{
    Input, InputEvent, InputState, NumberInput, NumberInputEvent, StepAction,
};
use gpui_component::label::Label;
use gpui_component::notification::Notification;
use gpui_component::progress::Progress;
use gpui_component::radio::{Radio, RadioGroup};
use gpui_component::scroll::ScrollableElement;
use gpui_component::tooltip::Tooltip;
use gpui_component::{Disableable, PixelsExt, StyledExt, WindowExt};
use gpui_component::{IconName, h_flex, v_flex};
use regex::Regex;
use rfd::FileDialog;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;
use vial_shared::config::Config;

use crate::crypto::{Commons, Schema, ToEncrypt};
use crate::utils::byte_size_to_readable;

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
    max_view_state: Entity<InputState>,
    max_day_count_state: Entity<InputState>,
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

        let max_view_state = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Enter max view count")
                .default_value("0")
                .pattern(Regex::new(r"^\d+$").unwrap())
        });
        let max_day_count_state = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Enter max day count")
                .default_value("0")
                .pattern(Regex::new(r"^\d+$").unwrap())
        });

        cx.subscribe_in(&max_view_state, window, |view, state, event, window, cx| {
            let max_views = view.config.get_max_views_verified();
            view.handle_incre_decre(window, state, cx, event, max_views);

            view.enforce_max(window, state, cx, max_views as i32);
        })
        .detach();

        cx.subscribe_in(&max_view_state, window, {
            move |view, state, ev: &InputEvent, window, cx| {
                if let InputEvent::Change = ev {
                    let max_views = view.config.get_max_views_verified();

                    view.enforce_max(window, state, cx, max_views as i32);
                }
            }
        })
        .detach();

        cx.subscribe_in(&max_day_count_state, window, {
            move |view, state, ev: &InputEvent, window, cx| {
                if let InputEvent::Change = ev {
                    let max_days = view.config.get_max_days_verified();
                    view.enforce_max(window, state, cx, max_days as i32);
                }
            }
        })
        .detach();

        cx.subscribe_in(
            &max_day_count_state,
            window,
            |view, state, event, window, cx| {
                let max_days = view.config.get_max_days_verified();
                view.handle_incre_decre(window, state, cx, event, max_days);

                view.enforce_max(window, state, cx, max_days as i32);
            },
        )
        .detach();

        let password = cx.new(|_| None);

        cx.observe_in(&password, window, |this, state, window, cx| {
            let value = state.read(cx);

            if value.is_some() {
                this.loading = true;
                this.start_encryption(window, cx);
            }
        })
        .detach();

        cx.subscribe_in(&to_encrypt, window, {
            move |this, _, ev: &InputEvent, _window, cx| {
                if let InputEvent::Change = ev {
                    this.update_progress(cx);

                    cx.notify();
                }
            }
        })
        .detach();

        cx.subscribe_in(&secret_url_state, window, {
            move |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::Change = ev {
                    this.sync_secret_url(window, cx);
                    cx.notify();
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
            max_view_state,
            max_day_count_state,
        }
    }

    fn enforce_max(
        &mut self,
        window: &mut Window,
        state: &Entity<InputState>,
        cx: &mut Context<Self>,
        max: i32,
    ) {
        let current_value = state.read(cx).value();

        if current_value.is_empty() {
            state.update(cx, |state, cx| {
                state.set_value("0", window, cx);
            });
        }

        if current_value.starts_with('0') && current_value.len() > 1 {
            let current_value = current_value[1..].to_string();
            state.update(cx, |state, cx| {
                state.set_value(current_value, window, cx);
            });
        }

        let Ok(parsed_value) = current_value.parse::<i32>() else {
            state.update(cx, |state, cx| {
                state.set_value("0", window, cx);
            });
            return;
        };

        if parsed_value > max {
            state.update(cx, |state, cx| {
                state.set_value(max.to_string(), window, cx);
            });
        }
    }

    fn handle_incre_decre(
        &mut self,
        window: &mut Window,
        state: &Entity<InputState>,
        cx: &mut Context<Self>,
        event: &NumberInputEvent,
        max_num: usize,
    ) {
        match event {
            NumberInputEvent::Step(step_action) => match step_action {
                StepAction::Increment => {
                    let read_value = state.read(cx).value();

                    let Ok(current_value) = read_value.parse::<i32>() else {
                        if read_value.is_empty() {
                            state.update(cx, |input, cx| {
                                input.set_value(String::from("1"), window, cx);
                            });
                        }
                        return;
                    };

                    let current_value = current_value + 1;

                    if current_value > max_num as i32 {
                        state.update(cx, |input, cx| {
                            input.set_value(max_num.to_string(), window, cx);
                        });
                        return;
                    }

                    state.update(cx, |input, cx| {
                        input.set_value(current_value.to_string(), window, cx);
                    });
                }
                StepAction::Decrement => {
                    let read_value = state.read(cx).value();
                    let Ok(current_value) = read_value.parse::<i32>() else {
                        if read_value.is_empty() {
                            state.update(cx, |input, cx| {
                                input.set_value(String::from("1"), window, cx);
                            });
                        }
                        return;
                    };

                    let current_value = current_value - 1;
                    state.update(cx, |input, cx| {
                        input.set_value(current_value.to_string(), window, cx);
                    });
                }
            },
        }
    }

    fn sync_secret_url(&mut self, window: &mut Window, cx: &mut Context<Self>) {
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

        let progress = self.full_size as f32 / self.config.get_max_size_verified() as f32;

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
                        let input_clone = input.clone();
                        let password = password.clone();
                        vec![
                            Button::new("ok").primary().label("Submit").on_click(
                                move |_, window, cx| {
                                    let input_value = input_clone.read(cx).value();
                                    password.update(cx, |state, cx| {
                                        *state = Some(input_value.to_string());
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
        } else {
            self.start_encryption(window, cx);
        }
    }

    fn start_encryption(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.to_encrypt.read(cx).value().to_string();
        let files = self.files.clone();
        let schema = Schema::from_index(self.schema_index);

        self.loading = true;

        let password = if let Schema::Password = schema {
            self.password.read(cx).clone()
        } else {
            None
        };

        let params = Commons {
            server_url: self.config.get_server_url(),
            web_ui_url: self.config.get_web_ui_url(),
            schema: Some(schema),
        };

        let Ok(max_days) = self.max_day_count_state.read(cx).value().parse::<usize>() else {
            return;
        };

        let max_days = if max_days == 0 { None } else { Some(max_days) };

        let Ok(max_view) = self.max_view_state.read(cx).value().parse::<i32>() else {
            return;
        };

        let max_view = if max_view == 0 { None } else { Some(max_view) };

        let encrypt_task = cx.background_spawn(async move {
            ToEncrypt::new(text, files, password, params, max_days, max_view).create_secret()
        });

        cx.spawn_in(window, async |this, cx| {
            let result = encrypt_task.await;

            if let Err(e) = result {
                if let Err(e) = cx.window_handle().update(cx, |_, window, cx| {
                    let notification =
                        Notification::error(format!("Error: {e:#}")).title("Encryption Failed");
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
                    this.secret_url = result.unwrap();
                    this.reset_all_states(cx, window);

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
            div().child(Label::new(format!("Files: {files_count}")))
        }
    }

    fn show_files(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        if self.files.is_empty() {
            return div();
        }

        v_flex().children(self.files.iter().enumerate().map(|(ix, path)| {
            let name = path.file_name().map_or_else(
                || "Unknown file".into(),
                |n| n.to_string_lossy().to_string(),
            );

            let size = byte_size_to_readable(path.metadata().map_or(0, |m| m.len()) as f64);

            let path = path.clone();

            h_flex()
                .items_center()
                .gap_2()
                .rounded_md()
                .px_4()
                .child(div().flex_1().truncate().child(Label::new(name)))
                .child(
                    div()
                        .w_24()
                        .text_align(TextAlign::Right)
                        .child(Label::new(size)),
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
                Animation::new(Duration::from_secs(1)).with_easing(ease_out_quint()),
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
            .children([password_radio, random_radio])
            .selected_index(Some(self.schema_index))
            .on_click(cx.listener(|view, selected_index: &usize, _, cx| {
                view.schema_index = *selected_index;
                cx.notify();
            }))
    }

    fn show_limitations(
        &mut self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> impl IntoElement {
        h_flex()
            .size_full()
            .gap_2()
            .child(
                GroupBox::new().outline().child(
                    v_flex()
                        .id("view-count")
                        .tooltip(|window, cx| {
                            Tooltip::new(
                                "How many times this secret can be viewed. If both set, whichever reaches first invalidates the secret. Set 0 to disable",
                            )
                            .build(window, cx)
                        })
                        .gap_2()
                        .child(
                            h_flex()
                                .size_full()
                                .justify_center()
                                .items_center()
                                .child(Label::new("Max view count")),
                        )
                        .child(NumberInput::new(&self.max_view_state).suffix(Label::new("Times"))),
                ),
            )
            .child(
                GroupBox::new().outline().child(
                    v_flex()
                        .id("day-count")
                        .tooltip(|window, cx| {
                            Tooltip::new(
                                "How many days this secret will be available. If both set, whichever reaches first invalidates the secret. Set 0 to disable",
                            )
                            .build(window, cx)
                        })
                        .gap_2()
                        .child(
                            h_flex()
                                .size_full()
                                .justify_center()
                                .items_center()
                                .child(Label::new("Max day count")),
                        )
                        .child(
                            NumberInput::new(&self.max_day_count_state).suffix(Label::new("Days")),
                        ),
                ),
            )
    }

    fn is_submit_disabled(&self, cx: &mut Context<Self>) -> bool {
        let Ok(max_day) = self.max_day_count_state.read(cx).value().parse::<usize>() else {
            return false;
        };

        let Ok(max_view) = self.max_view_state.read(cx).value().parse::<usize>() else {
            return false;
        };

        self.full_size == 0
            || self.full_size > self.config.get_max_size_verified() as u64
            || max_day > self.config.get_max_days_verified()
            || max_view > self.config.get_max_views_verified()
            || max_day == 0 && max_view == 0
            || self.loading
    }

    fn reset_all_states(&mut self, cx: &mut Context<Self>, window: &mut Window) {
        self.loading = false;

        self.to_encrypt.update(cx, |input, cx| {
            input.set_value(String::new(), window, cx);
        });

        self.files.clear();
        self.update_progress(cx);
    }

    pub fn update_config(&mut self, cx: &mut Context<Self>, config: &Config) {
        self.config = config.clone();
        self.update_progress(cx);
    }
}

impl Render for SendView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.sync_secret_url(window, cx);

        v_flex()
            .gap_2()
            .h_full()
            .child(Input::new(&self.to_encrypt))
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
                            "{} of {} used",
                            byte_size_to_readable(self.full_size as f64),
                            byte_size_to_readable(self.config.get_max_size_verified() as f64)
                        ))
                        .font_semibold(),
                    ),
            )
            .child(div().py_2().child(self.show_limitations(window, cx)))
            .child(
                v_flex()
                    .py_2()
                    .justify_center()
                    .items_center()
                    .child(self.show_schema_choice(window, cx)),
            )
            .child(
                h_flex().justify_center().items_center().pt_6().child(
                    Button::new("Submit")
                        .label("Submit")
                        .disabled(self.is_submit_disabled(cx))
                        .primary()
                        .loading(self.loading)
                        .w_2_5()
                        .on_click(cx.listener(Self::submit)),
                ),
            )
            .child(self.show_url_input(window, cx))
    }
}
