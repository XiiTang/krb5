use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
fn run(command: &mut Command) {
    let output = command.output().expect("start Kerberos build tool");
    assert!(
        output.status.success(),
        "Kerberos build failed: {:?}\n{}\n{}",
        command,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn copy(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == "autom4te.cache" || name == "configure" || name == "configure~" {
            continue;
        }
        let target = to.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy(&entry.path(), &target)
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=runtime");
    println!("cargo:rerun-if-env-changed=BOUNDLESS_KRB5_BUILD_DIR");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target == "windows" {
        windows(&root, &out);
        return;
    }
    let native = if let Some(path) = env::var_os("BOUNDLESS_KRB5_BUILD_DIR") {
        PathBuf::from(path)
    } else {
        let source = out.join("source");
        let build = out.join("native");
        if source.exists() {
            fs::remove_dir_all(&source).unwrap();
        }
        if build.exists() {
            fs::remove_dir_all(&build).unwrap();
        }
        copy(&root.join("src"), &source);
        fs::create_dir_all(&build).unwrap();
        run(Command::new("autoconf").current_dir(&source));
        run(Command::new("autoheader").current_dir(&source));
        run(Command::new(source.join("configure"))
            .current_dir(&build)
            .args([
                "--enable-static",
                "--disable-shared",
                "--enable-boundless-runtime",
                "--disable-pkinit",
                "--disable-nls",
                "--without-keyutils",
                "--without-system-verto",
                "--without-readline",
            ])
            .arg(format!("--prefix={}", out.join("private").display()))
            .env("CFLAGS", "-O2 -fPIC"));
        run(Command::new("make")
            .current_dir(&build)
            .arg("update-autoconf-h"));
        for dir in ["util", "include", "lib"] {
            run(Command::new("make").current_dir(build.join(dir)).arg("-j2"));
        }
        build
    };
    let config =
        fs::read_to_string(native.join("include/autoconf.h")).expect("private Kerberos config");
    assert!(
        config.contains("#define BOUNDLESS_STATIC_GSS 1"),
        "Kerberos must use the isolated runtime build"
    );
    cc::Build::new()
        .file(root.join("runtime/native.c"))
        .include(root.join("runtime"))
        .include(native.join("include"))
        .include(root.join("src/include"))
        .warnings(true)
        .compile("boundless_kerberos_bridge");
    println!(
        "cargo:rustc-link-search=native={}",
        native.join("lib").display()
    );
    for lib in ["gssapi_krb5", "krb5", "k5crypto", "com_err", "krb5support"] {
        println!("cargo:rustc-link-lib=static={lib}");
    }
    println!("cargo:rustc-link-lib=resolv");
    if target == "linux" {
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=pthread");
    }
}

fn windows(root: &Path, out: &Path) {
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ARCH").unwrap(),
        "x86_64",
        "Windows private Kerberos currently requires x86_64"
    );
    let source = out.join("source");
    if source.exists() {
        fs::remove_dir_all(&source).unwrap();
    }
    copy(&root.join("src"), &source);
    let make = |directory: &Path, args: &[&str]| {
        run(Command::new("nmake")
            .current_dir(directory)
            .env("NODEBUG", "1")
            .env("NO_LEASH", "1")
            .arg("/nologo")
            .args(args));
    };
    make(&source, &["/f", "Makefile.in", "prep-windows"]);
    make(&source, &["Makefile-windows"]);
    for part in ["include", "util", "lib"] {
        make(&source.join(part), &[]);
    }
    let libraries = source.join("lib/obj/AMD64/rel");
    // Cargo adds OUT_DIR link-search directories to the execution loader path.
    // Package builders copy this exact private closure beside the product.
    for name in ["gssapi64", "krb5_64", "comerr64", "k5sprt64"] {
        for extension in ["lib", "dll"] {
            let filename = format!("{name}.{extension}");
            fs::copy(libraries.join(&filename), out.join(&filename)).unwrap();
        }
    }
    cc::Build::new()
        .file(root.join("runtime/native.c"))
        .include(root.join("runtime"))
        .include(source.join("include"))
        .warnings(true)
        .compile("boundless_kerberos_bridge");
    println!("cargo:rustc-link-search=native={}", out.display());
    for name in ["gssapi64", "krb5_64", "comerr64", "k5sprt64"] {
        println!("cargo:rustc-link-lib=dylib={name}");
    }
}
