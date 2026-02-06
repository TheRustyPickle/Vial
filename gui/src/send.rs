use gpui::*;
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::clipboard::Clipboard;
use gpui_component::group_box::{GroupBox, GroupBoxVariants};
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::label::Label;
use gpui_component::progress::Progress;
use gpui_component::scroll::ScrollableElement;
use gpui_component::{ActiveTheme as _, Disableable, StyledExt};
use gpui_component::{IconName, h_flex, v_flex};
use rfd::FileDialog;
use std::collections::BTreeSet;
use std::path::PathBuf;

const MAX_SIZE: u64 = 1024 * 1024 * 5 + 200;

pub struct SendView {
    to_encrypt: Entity<InputState>,
    secret_url_state: Entity<InputState>,
    secret_url: String,
    files: BTreeSet<PathBuf>,
    full_size: u64,
    file_size: u64,
    progress: f32,
    _subscriptions: Vec<Subscription>,
}

impl SendView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
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

        let mut subscriptions = vec![cx.subscribe_in(&to_encrypt, window, {
            move |this, _, ev: &InputEvent, _window, cx| {
                if let InputEvent::Change = ev {
                    this.update_progress(cx);

                    cx.notify()
                }
            }
        })];

        subscriptions.push(cx.subscribe_in(&secret_url_state, window, {
            move |this, _, ev: &InputEvent, window, cx| {
                if let InputEvent::Change = ev {
                    this.reset_secret_url(window, cx);
                    cx.notify()
                }
            }
        }));

        Self {
            to_encrypt,
            secret_url: String::new(),
            secret_url_state,
            files: BTreeSet::new(),
            file_size: 0,
            full_size: 0,
            progress: 0.0,
            _subscriptions: subscriptions,
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
        let _value = self.to_encrypt.read(cx).value();
        self.secret_url = String::from("https://google.com");
        self.reset_secret_url(window, cx);
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
}

impl Render for SendView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
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
                            MAX_SIZE as f64 / (1024 * 1024) as f64
                        ))
                        .font_semibold(),
                    ),
            )
            .child(
                h_flex().justify_center().items_center().pt_10().child(
                    Button::new("Submit")
                        .label("Submit")
                        .disabled(self.full_size == 0 || self.full_size > MAX_SIZE)
                        .primary()
                        .w_2_5()
                        .on_click(cx.listener(Self::submit)),
                ),
            )
            .child(
                v_flex()
                    .w_full()
                    .items_center()
                    .h_full()
                    .justify_end()
                    .pb_10()
                    .pt_5()
                    .child(
                        Input::new(&self.secret_url_state)
                            .border_2()
                            .rounded_lg()
                            .suffix(Clipboard::new("clipboard").value(self.secret_url.clone())),
                    ),
            )
    }
}
