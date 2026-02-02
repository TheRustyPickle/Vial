use gpui::*;
use gpui_component::{
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState},
    v_flex,
};

use crate::MainWindow;

pub struct SendView {
    input_state: Entity<InputState>,
    display_text: SharedString,
    _subscriptions: Vec<Subscription>,
}

impl SendView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let input_state = cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .auto_grow(10, 10)
                .placeholder("Enter text to encrypt")
                .searchable(true)
                .soft_wrap(true)
        });

        let _subscriptions = vec![cx.subscribe_in(&input_state, window, {
            let input_state = input_state.clone();
            move |this, _, ev: &InputEvent, _window, cx| {
                if let InputEvent::Change = ev {
                    let value = input_state.read(cx).value();
                    this.display_text = format!("Hello, {}!", value).into();
                    cx.notify()
                }
            }
        })];

        Self {
            input_state,
            display_text: SharedString::default(),
            _subscriptions,
        }
    }
}

impl Render for SendView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .justify_center()
            .items_center()
            .gap_2()
            .child(Input::new(&self.input_state))
            .child(Button::new("Submit").label("Submit").primary().w_1_5())
    }
}

