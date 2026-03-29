use gpui::prelude::FluentBuilder;
use gpui::*;
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::input::{Input, InputState, NumberInput, NumberInputEvent, StepAction};
use gpui_component::notification::Notification;
use gpui_component::tooltip::Tooltip;
use gpui_component::{IconName, WindowExt as _, h_flex, v_flex};
use rfd::FileDialog;
use std::path::PathBuf;
use vial_shared::config::Config;

pub struct ConfigView {
    config: Config,
    download_path: Entity<InputState>,
    server_url: Entity<InputState>,
    max_size: Entity<InputState>,
    web_ui_url: Entity<InputState>,
    max_views: Entity<InputState>,
    max_days: Entity<InputState>,
    database_url: Entity<InputState>,
    port: Entity<InputState>,
    address: Entity<InputState>,
}

#[derive(Clone, Copy)]
pub enum ConfigEvent {
    Reloaded,
}

impl EventEmitter<ConfigEvent> for ConfigView {}

impl ConfigView {
    pub fn new(config: Config, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let download_path = if let Some(download_path) = &config.download_path {
            download_path.to_string_lossy().to_string()
        } else {
            String::new()
        };

        let database_url = config.database_url.clone().unwrap_or_default();

        let download_path = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(download_path)
                .placeholder("Path for downloading files from a secret")
                .multi_line(false)
        });

        let server_url = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.get_server_url())
                .placeholder("https://yourserver.com/api/secrets")
                .multi_line(false)
        });

        let web_ui_url = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.get_web_ui_url())
                .placeholder("https://yoursite.com/secrets")
                .multi_line(false)
        });

        let max_size = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.get_max_size().to_string())
                .placeholder("5mb = 1024 * 1024 * 5")
                .multi_line(false)
        });

        let max_views = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("View count in number")
                .multi_line(false)
        });

        let max_days = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.get_max_days().to_string())
                .placeholder("Days in number")
                .multi_line(false)
        });

        let database_url = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(database_url)
                .placeholder("postgresql://postgres:asdf@127.0.0.1:5432/asdf")
                .multi_line(false)
        });
        let port = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.get_port().to_string())
                .placeholder("Port number: 8080")
                .multi_line(false)
        });
        let address = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.get_address())
                .placeholder("Address to bind to: 127.0.0.1")
                .multi_line(false)
        });

        cx.subscribe_in(&max_views, window, |view, state, event, window, cx| {
            view.handle_incre_decre(window, state, cx, event);
        })
        .detach();

        cx.subscribe_in(&max_days, window, |view, state, event, window, cx| {
            view.handle_incre_decre(window, state, cx, event);
        })
        .detach();

        cx.subscribe_in(&max_size, window, |view, state, event, window, cx| {
            view.handle_incre_decre(window, state, cx, event);
        })
        .detach();

        cx.subscribe_in(&port, window, |view, state, event, window, cx| {
            view.handle_incre_decre(window, state, cx, event);
        })
        .detach();

        Self {
            download_path,
            server_url,
            max_size,
            web_ui_url,
            max_days,
            database_url,
            port,
            address,
            config,
            max_views,
        }
    }

    fn labeled_input(
        &self,
        label: &str,
        state: &Entity<InputState>,
        number: bool,
        tooltip_text: &str,
    ) -> impl IntoElement {
        let tooltip_text = tooltip_text.to_string();

        v_flex()
            .id(SharedString::new(format!("labeled-input-{label}")))
            .tooltip(move |window, cx| Tooltip::new(tooltip_text.to_string()).build(window, cx))
            .w_full()
            .gap_2()
            .child(div().text_sm().child(label.to_string()))
            .when(number, |d| d.child(NumberInput::new(state)))
            .when(!number, |d| d.child(Input::new(state)))
    }

    fn labeled_input_folder(
        &self,
        cx: &mut Context<Self>,
        label: &str,
        state: &Entity<InputState>,
        tooltip_text: &str,
    ) -> impl IntoElement {
        let tooltip_text = tooltip_text.to_string();

        v_flex()
            .id("labeled-input-folder")
            .tooltip(move |window, cx| Tooltip::new(tooltip_text.to_string()).build(window, cx))
            .w_full()
            .gap_2()
            .child(div().text_sm().child(label.to_string()))
            .child(
                h_flex().gap_2().child(Input::new(state)).child(
                    Button::new("folder")
                        .outline()
                        .icon(IconName::Folder)
                        .on_click(cx.listener(Self::get_folder)),
                ),
            )
    }

    fn get_folder(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        let Some(folder) = FileDialog::new().pick_folder() else {
            return;
        };

        self.download_path.update(cx, |state, cx| {
            state.set_value(folder.to_string_lossy().to_string(), window, cx)
        });
    }

    fn save_config(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        let server_url = self.server_url.read(cx).value().trim().to_string();
        let web_ui_url = self.web_ui_url.read(cx).value().trim().to_string();
        let max_size = self.max_size.read(cx).value().trim().to_string();
        let max_days = self.max_days.read(cx).value().trim().to_string();
        let max_views = self.max_views.read(cx).value().trim().to_string();
        let download_path = self.download_path.read(cx).value().trim().to_string();
        let database_url = self.database_url.read(cx).value().trim().to_string();
        let port = self.port.read(cx).value().trim().to_string();
        let address = self.address.read(cx).value().trim().to_string();

        let server_url = if server_url.is_empty() {
            None
        } else {
            Some(server_url)
        };

        let web_ui_url = if web_ui_url.is_empty() {
            None
        } else {
            Some(web_ui_url)
        };

        let database_url = if database_url.is_empty() {
            None
        } else {
            Some(database_url)
        };

        let port = if port.is_empty() {
            None
        } else {
            port.parse().ok()
        };

        let address = if address.is_empty() {
            None
        } else {
            Some(address)
        };

        let max_size = if max_size.is_empty() {
            None
        } else {
            max_size.parse().ok()
        };

        let max_days = if max_days.is_empty() {
            None
        } else {
            max_days.parse().ok()
        };

        let max_views = if max_views.is_empty() {
            None
        } else {
            max_views.parse().ok()
        };

        let download_path = if download_path.is_empty() {
            None
        } else {
            Some(PathBuf::from(download_path))
        };

        self.config.download_path = download_path;
        self.config.server_url = server_url;
        self.config.web_ui_url = web_ui_url;
        self.config.max_size = max_size;
        self.config.max_days = max_days;
        self.config.max_views = max_views;
        self.config.database_url = database_url;
        self.config.port = port;
        self.config.address = address;

        if let Err(e) = self.config.save_config() {
            let notification =
                Notification::error(format!("Error: {e:#}")).title("Failed to save config");
            window.push_notification(notification, cx);
        } else {
            let notification = Notification::success("Config saved successfully").title("Success");
            window.push_notification(notification, cx);
            cx.emit(ConfigEvent::Reloaded);
        }
    }

    fn reset_config(&mut self, _: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        self.server_url.update(cx, |state, cx| {
            state.set_value(self.config.get_server_url(), window, cx);
        });

        self.web_ui_url.update(cx, |state, cx| {
            state.set_value(self.config.get_web_ui_url(), window, cx);
        });

        self.max_size.update(cx, |state, cx| {
            state.set_value(self.config.get_max_size().to_string(), window, cx);
        });

        self.max_days.update(cx, |state, cx| {
            state.set_value(self.config.get_max_days().to_string(), window, cx);
        });

        self.max_views.update(cx, |state, cx| {
            state.set_value(self.config.get_max_views().to_string(), window, cx);
        });

        let download_path = if let Some(download_path) = &self.config.download_path {
            download_path.to_string_lossy().to_string()
        } else {
            String::new()
        };

        self.download_path.update(cx, |state, cx| {
            state.set_value(download_path, window, cx);
        });

        self.database_url.update(cx, |state, cx| {
            state.set_value(
                self.config.database_url.clone().unwrap_or_default(),
                window,
                cx,
            );
        });

        self.port.update(cx, |state, cx| {
            state.set_value(self.config.get_port().to_string(), window, cx);
        });

        self.address.update(cx, |state, cx| {
            state.set_value(self.config.get_address(), window, cx);
        });
    }

    fn handle_incre_decre(
        &mut self,
        window: &mut Window,
        state: &Entity<InputState>,
        cx: &mut Context<Self>,
        event: &NumberInputEvent,
    ) {
        match event {
            NumberInputEvent::Step(step_action) => match step_action {
                StepAction::Increment => {
                    let read_value = state.read(cx).value();

                    if read_value.is_empty() {
                        state.update(cx, |input, cx| {
                            input.set_value(String::from("1"), window, cx);
                        });
                        return;
                    }

                    let Ok(current_value) = read_value.parse::<i32>() else {
                        return;
                    };

                    let current_value = current_value + 1;

                    state.update(cx, |input, cx| {
                        input.set_value(current_value.to_string(), window, cx);
                    });
                }
                StepAction::Decrement => {
                    let read_value = state.read(cx).value();

                    if read_value.is_empty() {
                        state.update(cx, |input, cx| {
                            input.set_value(String::from("1"), window, cx);
                        });
                        return;
                    }

                    let Ok(current_value) = read_value.parse::<i32>() else {
                        return;
                    };

                    let current_value = current_value - 1;

                    if current_value <= 0 {
                        state.update(cx, |input, cx| {
                            input.set_value(String::from(""), window, cx);
                        });
                        return;
                    }

                    state.update(cx, |input, cx| {
                        input.set_value(current_value.to_string(), window, cx);
                    });
                }
            },
        }
    }
}

impl Render for ConfigView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let server_tooltip = "Set the secrets API base URL. This must be the endpoint that accepts:

POST to create a new secret
GET /{id} to retrieve an existing secret

Defaults to https://rustypickle.onrender.com/api/secrets";

        let web_ui_tooltip =
            "Set the secrets web UI base URL. This must be an endpoint that accepts:

/{id} parameter

Defaults to https://rustypickle.onrender.com/secrets";

        let download_path_tooltip = "Set the default download directory for when downloading files. Defaults to the current working directory.";

        let max_size_tooltip = "Set the maximum allowed secret size (in bytes).
Unless a different server url is used than the default one, this value is ignored.

Defaults to 5 MB plus a small overhead for encryption metadata.";

        let max_days_tooltip = "Set the maximum days a secret can be viewed.
Unless a different server url is used than the default one, this value is ignored.

Defaults to 30 days.";

        let max_view_tooltip = "Set the maximum allowed secret views count.
Unless a different server url is used than the default one, this value is ignored.

Defaults to 1000 views.";

        let address_tooltip = "Set the address to bind to when starting the server bin (vial-server). Defaults to 127.0.0.1.";

        let port_tooltip =
            "Set the port to bind to when starting the server bin (vial-server). Defaults to 8080.";

        let db_tooltip = "Set the database URL to use when starting the server bin (vial-server). No default value and must be set when starting the server.";

        v_flex()
            .w_full()
            .h_full()
            .p_6()
            .gap_4()
            .child(
                v_flex()
                    .w_full()
                    .gap_4()
                    .child(
                        h_flex()
                            .gap_2()
                            .w_full()
                            .justify_center()
                            .child(self.labeled_input(
                                "Server URL",
                                &self.server_url,
                                false,
                                server_tooltip,
                            ))
                            .child(self.labeled_input(
                                "Web UI URL",
                                &self.web_ui_url,
                                false,
                                web_ui_tooltip,
                            )),
                    )
                    .child(self.labeled_input_folder(
                        cx,
                        "Download Path",
                        &self.download_path,
                        download_path_tooltip,
                    )),
            )
            .child(
                v_flex().gap_4().child(
                    h_flex()
                        .gap_2()
                        .w_full()
                        .justify_center()
                        .child(self.labeled_input(
                            "Max Views",
                            &self.max_views,
                            true,
                            max_view_tooltip,
                        ))
                        .child(self.labeled_input(
                            "Max Days",
                            &self.max_days,
                            true,
                            max_days_tooltip,
                        ))
                        .child(self.labeled_input(
                            "Max Size (bytes)",
                            &self.max_size,
                            true,
                            max_size_tooltip,
                        )),
                ),
            )
            .child(
                v_flex().gap_4().child(
                    h_flex()
                        .gap_2()
                        .w_full()
                        .justify_center()
                        .child(self.labeled_input("Address", &self.address, false, address_tooltip))
                        .child(self.labeled_input("Port", &self.port, true, port_tooltip)),
                ),
            )
            .child(v_flex().gap_4().child(self.labeled_input(
                "Postgres Database URL",
                &self.database_url,
                false,
                db_tooltip,
            )))
            .child(
                h_flex()
                    .mt_4()
                    .w_full()
                    .justify_center()
                    .items_center()
                    .gap_2()
                    .child(
                        Button::new("Save")
                            .label("Save")
                            .primary()
                            .w_32()
                            .on_click(cx.listener(Self::save_config)),
                    )
                    .child(
                        Button::new("Reset")
                            .label("Reset")
                            .danger()
                            .w_32()
                            .on_click(cx.listener(Self::reset_config)),
                    ),
            )
    }
}
