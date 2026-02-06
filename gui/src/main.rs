mod send;

use gpui::*;
use gpui_component::tab::{Tab, TabBar};
use gpui_component::{Root, Theme, h_flex, v_flex};
use gpui_component_assets::Assets;

use crate::send::SendView;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum MainTab {
    #[default]
    Send = 0,
    Receive = 1,
    Config = 2,
}

impl MainTab {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Send,
            1 => Self::Receive,
            2 => Self::Config,
            _ => panic!("This should never happen"),
        }
    }
}

struct MainWindow {
    active_tab: MainTab,
    send_view: Entity<SendView>,
}

impl MainWindow {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let send_entity = cx.new(|cx| SendView::new(window, cx));

        Self {
            active_tab: MainTab::default(),
            send_view: send_entity,
        }
    }

    fn set_active_tab(&mut self, index: usize, _window: &mut Window, cx: &mut Context<Self>) {
        self.active_tab = MainTab::from_index(index);
        cx.notify();
    }

    fn render_tab(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        match self.active_tab {
            MainTab::Send => v_flex().size_full().child(self.send_view.clone()),
            _ => div().child(self.send_view.clone()),
        }
    }
}

impl Render for MainWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let active_tab_index = self.active_tab as usize;

        v_flex()
            .size_full()
            .items_center()
            .gap_2()
            .child(
                h_flex()
                    .pt_2()
                    .items_center()
                    .justify_center()
                    .w_3_5()
                    .child(
                        TabBar::new("tabs")
                            .w_full()
                            .segmented()
                            .selected_index(active_tab_index)
                            .on_click(cx.listener(|this, ix: &usize, window, cx| {
                                this.set_active_tab(*ix, window, cx);
                            }))
                            .items_center()
                            .justify_center()
                            .child(Tab::new().label("Send").flex_1())
                            .child(Tab::new().label("Receive").flex_1())
                            .child(Tab::new().label("Config").flex_1()),
                    ),
            )
            .child(v_flex().h_full().w_4_5().child(self.render_tab(window, cx)))
    }
}

fn main() {
    let app = Application::new().with_assets(Assets);

    app.run(move |cx| {
        // This must be called before using any GPUI Component features.
        gpui_component::init(cx);

        cx.spawn(async move |cx| {
            cx.open_window(WindowOptions::default(), |window, cx| {
                window.activate_window();
                window.set_window_title("Vial");

                window.resize(Size::new(850.0.into(), 800.0.into()));

                Theme::sync_system_appearance(Some(window), cx);

                let view = cx.new(|cx| MainWindow::new(window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            })?;

            Ok::<_, anyhow::Error>(())
        })
        .detach();
    });
}
