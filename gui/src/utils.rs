pub fn byte_size_to_readable(len: f64) -> String {
    let kb = len / 1024.0;

    if kb > 1024.0 {
        let mb = kb / 1024.0;

        if mb > 1024.0 {
            let gb = mb / 1024.0;
            format!("{gb:.2} GB")
        } else {
            format!("{mb:.2} MB")
        }
    } else {
        format!("{kb:.2} KB")
    }
}
