extern crate cc;

fn main() {
    cc::Build::new()
        .file("shs1-c/src/shs1.c")
        .include("shs1-c/src")
        .compile("libshs1.a");
}
