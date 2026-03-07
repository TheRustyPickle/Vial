use gpui::prelude::FluentBuilder;
use gpui::*;
use gpui_component::button::Button;
use gpui_component::input::{Input, InputEvent, InputState, NumberInput};
use gpui_component::notification::Notification;
use gpui_component::scroll::ScrollableElement;
use gpui_component::tooltip::Tooltip;
use gpui_component::{IconName, h_flex, v_flex};
use rfd::FileDialog;
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

impl ConfigView {
    pub fn new(config: Config, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let download_path = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Path for downloading files from a secret")
                .multi_line(false)
        });

        let server_url = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("https://yourserver.com/api/secrets")
                .multi_line(false)
        });

        let web_ui_url = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("https://yoursite.com/secrets")
                .multi_line(false)
        });

        let max_size = cx.new(|cx| {
            InputState::new(window, cx)
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
                .placeholder("Days in number")
                .multi_line(false)
        });

        let database_url = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("postgresql://postgres:asdf@127.0.0.1:5432/asdf")
                .multi_line(false)
        });
        let port = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Port number: 8080")
                .multi_line(false)
        });
        let address = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Address to bind to: 127.0.0.1")
                .multi_line(false)
        });

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
}

impl Render for ConfigView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
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
                                "Set the secrets API base URL. This must be the endpoint that accepts:

POST to create a new secret
GET /{id} to retrieve an existing secret

Defaults to https://rustypickle.onrender.com/api/secrets"
                                ,
                            ))
                            .child(self.labeled_input(
                                "Web UI URL",
                                &self.web_ui_url,
                                false,
                                "Set the secrets web UI base URL. This must be an endpoint that accepts:

/{id} parameter

Defaults to https://rustypickle.onrender.com/secrets",
                            )),
                    )
                    .child(self.labeled_input_folder(cx, "Download Path", &self.download_path, "Set the default download directory for when downloading files. Defaults to the current working directory.")),
            )
            .child(
                v_flex().gap_4().child(
                    h_flex()
                        .gap_2()
                        .w_full()
                        .justify_center()
                        .child(self.labeled_input("Max Views", &self.max_views, true, "Set the maximum allowed secret views count.
Unless a different server url is used than the default one, this value is ignored.

Defaults to 1000 views."))
                        .child(self.labeled_input("Max Days", &self.max_days, true, "Set the maximum days a secret can be viewed.
Unless a different server url is used than the default one, this value is ignored.

Defaults to 30 days."))
                        .child(self.labeled_input("Max Size (bytes)", &self.max_size, true, "Set the maximum allowed secret size (in bytes).
Unless a different server url is used than the default one, this value is ignored.

Defaults to 5 MB plus a small overhead for encryption metadata.")),
                ),
            )
            .child(
                v_flex().gap_4().child(
                    h_flex()
                        .gap_2()
                        .w_full()
                        .justify_center()
                        .child(self.labeled_input("Address", &self.address, false, "Set the address to bind to when starting the server bin (vial-server). Defaults to 127.0.0.1."))
                        .child(self.labeled_input("Port", &self.port, true, "Set the port to bind to when starting the server bin (vial-server). Defaults to 8080.")),
                ),
            )
            .child(v_flex().gap_4().child(self.labeled_input(
                "Postgres Database URL",
                &self.database_url,
                false,
                "Set the database URL to use when starting the server bin (vial-server). No default value and must be set when starting the server.",
            )))
    }
}
