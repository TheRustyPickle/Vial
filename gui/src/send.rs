use gpui::*;
use gpui_component::ActiveTheme as _;
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::group_box::{GroupBox, GroupBoxVariants};
use gpui_component::input::{Input, InputState};
use gpui_component::label::Label;
use gpui_component::{IconName, h_flex, v_flex};
use rfd::FileDialog;
use std::path::PathBuf;

pub struct SendView {
    input_state: Entity<InputState>,
    files: Vec<PathBuf>,
}

impl SendView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .auto_grow(7, 7)
                .placeholder("Enter text to encrypt")
                .searchable(true)
                .soft_wrap(true)
        });

        Self {
            input_state,
            files: vec![],
        }
    }

    fn submit(&mut self, _: &ClickEvent, _window: &mut Window, cx: &mut Context<Self>) {
        let value = self.input_state.read(cx).value();
        println!("Submitted: {}", value);
    }

    fn get_files(&mut self, _: &ClickEvent, _window: &mut Window, _cx: &mut Context<Self>) {
        let Some(files) = FileDialog::new().pick_files() else {
            return;
        };

        self.files = files;
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

            h_flex()
                .items_center()
                .gap_3()
                .rounded_md()
                .px_2()
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
                        .on_click(cx.listener(move |this, _, _, _| {
                            this.files.remove(ix);
                        })),
                )
        }))
    }
}

impl Render for SendView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .gap_2()
            .child(
                Input::new(&self.input_state)
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
                        .child(self.show_files(cx)),
                ),
            )
            .child(
                h_flex()
                    .justify_center()
                    .items_center()
                    .pt_10()
                    .pb_5()
                    .child(
                        Button::new("Submit")
                            .label("Submit")
                            .primary()
                            .w_2_5()
                            .on_click(cx.listener(Self::submit)),
                    ),
            )
    }
}
