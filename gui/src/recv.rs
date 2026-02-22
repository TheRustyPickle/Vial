use gpui::prelude::FluentBuilder;
use gpui::*;
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::clipboard::Clipboard;
use gpui_component::group_box::{GroupBox, GroupBoxVariants};
use gpui_component::input::{
    Input, InputEvent, InputState, NumberInput, NumberInputEvent, StepAction,
};
use gpui_component::label::Label;
use gpui_component::notification::Notification;
use gpui_component::radio::{Radio, RadioGroup};
use gpui_component::scroll::ScrollableElement;
use gpui_component::tooltip::Tooltip;
use gpui_component::{ActiveTheme as _, Disableable, PixelsExt, StyledExt, WindowExt};
use gpui_component::{IconName, h_flex, v_flex};
use regex::Regex;
use rfd::FileDialog;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;
use vial_shared::FullSecret;
use vial_shared::config::Config;

use crate::crypto::{Schema, ToEncrypt, Urls};

pub struct ReceiveView {
    config: Config,
    url_state: Entity<InputState>,
    key_state: Entity<InputState>,
    decrypt_key: Entity<Option<(String, String)>>,
    decrypted_state: Entity<Option<FullSecret>>,
    schema_index: usize,
    loading: bool,
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

        let decrypted_state = cx.new(|_| None);
        let decrypt_key = cx.new(|_| None);

        cx.observe_in(&decrypt_key, window, |this, state, window, cx| {
            let value = state.read(cx);

            if value.is_some() {
                this.loading = true;
                println!("Decrypting secret");
            }
        })
        .detach();

        Self {
            config,
            url_state,
            key_state,
            decrypt_key,
            decrypted_state,
            loading: false,
            schema_index: 0,
        }
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
                state.set_value(trimmed.to_string(), window, cx);
            });
        };
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

        println!("Secret ID: {}", secret_id);

        let key = secret_id.split_once('#');

        if let Some((id, key)) = key {
            self.decrypt_key.update(cx, |state, cx| {
                *state = Some((id.to_string(), key.to_string()));
                cx.notify()
            })
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
                                        *state = Some((id.to_string(), input_value.to_string()));
                                        cx.notify()
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
}

impl Render for ReceiveView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .gap_2()
            .h_full()
            .when(self.decrypted_state.read(cx).is_some(), |div| {
                div.child(Label::new("Decrypted content"))
            })
            .when(self.decrypted_state.read(cx).is_none(), |d| {
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
                        .child(div().py_2().child(self.show_schema_choice(window, cx)))
                        .child(
                            Button::new("decrypt")
                                .label("Submit")
                                .primary()
                                .loading(self.loading)
                                .w_2_5()
                                .on_click(cx.listener(Self::submit)),
                        ),
                )
            })
    }
}
