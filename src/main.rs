#![allow(dead_code)] // TODO: remove me
#![allow(unused_macros)]
#![allow(unused_variables)] // TODO: remove me

macro_rules! error {
    ($($arg:tt)*) => (eprintln!("\x1b[31m{}:{} {}\x1b[0m", file!(), line!(), format_args!($($arg)*)));
}

macro_rules! warn {
    ($($arg:tt)*) => (eprintln!("\x1b[33m{}:{} {}\x1b[0m", file!(), line!(), format_args!($($arg)*)));
}

macro_rules! info {
    ($($arg:tt)*) => (eprintln!("\x1b[34m{}:{} {}\x1b[0m", file!(), line!(), format_args!($($arg)*)));
}

macro_rules! debug {
    ($($arg:tt)*) => (eprintln!("\x1b[37m{}:{} {}\x1b[0m", file!(), line!(), format_args!($($arg)*)));
}

// -----------------------------------------------------------------------------
// cli

pub fn main() -> Result<(), failure::Error> {
    let arg_matches = clap::App::new("convert-patch")
        .version("0.1")
        .about("Convert git-format-patch for git-am in another repository and/or directory")
        .author("Wataru Ashihara")
        .arg(
            clap::Arg::with_name("from_to")
                .long("from-to")
                .value_name("FROMTO")
                .takes_value(true)
                .multiple(true)
                .help("todo help (e.g. --from-to=dir_a/,dir_b/ --from-to=dir1/dir2/,dir3/)"),
        )
        .arg(clap::Arg::with_name("import_template")
            .long("import-template")
            .value_name("IMPORT_TEMPLATE")
            .help("todo help (e.g. --import-template='Imported from: https://github.com/wataash/repo/commit/{}')"))
        .arg(clap::Arg::with_name("import_sha1_len")
            .long("import-sha1-len")
            .value_name("IMPORT_SHA1_LEN")
            .requires("import_template")
            .help("todo help"))
        .get_matches();

    let mut replaces = Vec::<(&str, &str)>::new();

    fn invalid_arg(err: failure::Error) -> Result<(), failure::Error> {
        error!("{}", err);
        Err(err)
    }

    match arg_matches.values_of_os("from_to") {
        None => {
            // --from-to not given
        }
        Some(os_values) => {
            for os_str in os_values {
                let s = match os_str.to_str() {
                    None => {
                        // (1st) 2nd 3rd 4th
                        return invalid_arg(format_err!(
                            "TODOth --from-to: invalid utf-8 argument"
                        ));
                    }
                    Some(x) => x,
                };
                if s.matches(",").count() != 1 {
                    let err = format_err!(
                        "--from-to {}: must have exactly one comma ({} given)",
                        s,
                        s.matches(",").count()
                    );
                    error!("{}", err);
                    return Err(err);
                }
                let mut from_to: std::str::Split<&str> = s.split(",");
                // let a: std::slice::Split;
                // a.next()
                let from = from_to.next().unwrap();
                let to = from_to.next().unwrap();
                replaces.push((from, to));
                let _breakpoint = 1;
            }
        }
    };

    let mut import_template = None::<&str>;
    if let Some(os_str) = arg_matches.value_of_os("import_template") {
        match os_str.to_str() {
            None => return invalid_arg(format_err!("--import-template: invalid utf-8 argument")),
            Some(x) => import_template = Some(x),
        };
    };

    let import_sha1_len: usize = if let Some(os_str) = arg_matches.value_of_os("import_sha1_len") {
        let s = match os_str.to_str() {
            None => return invalid_arg(format_err!("--import-sha1-len: invalid utf-8 argument")),
            Some(x) => x,
        };
        match s.parse() {
            Ok(x) => x,
            Err(err) => {
                return invalid_arg(format_err!("--import-sha1-len: invalid value: {}", err));
            }
        }
    } else {
        7
    };

    let config = Config {
        replaces,
        import_template,
        import_sha1_len,
    };
    let mut formatted_patch = String::new();
    use std::io::Read;
    let _tmp = std::io::stdin().read_to_string(&mut formatted_patch)?;
    let patches2 = convert_formatted_patch(formatted_patch.as_str(), &config);
    print!("{}", patches2);
    let _breakpoint = 1;

    Ok(())
}

// -----------------------------------------------------------------------------
// lib

// struct Config<'a> {
pub struct Config<'a, 'b, 'c> {
    replaces: Vec<(&'a str, &'b str)>,
    import_template: Option<&'c str>,
    import_sha1_len: usize,
}

// asm bindgen
pub fn convert_formatted_patch(patches: &str, config: &Config) -> String {
    let patches = mail_split(&patches);
    let mut patches2 = String::new();
    for patch in patches {
        let patch2 =
            convert_patch(patch, &config).unwrap_or_else(|x| format!("\nerror: {}\n\n", x));
        patches2.push_str(&patch2);
    }
    patches2
}

#[derive(Default)]
struct Patch<'a> {
    line_num: usize,
    buf: &'a str,
    sha1: String,
}

/// analogue to git-mailsplit
fn mail_split(patch: &str) -> Vec<Patch> {
    let re = re(
        r"(From [0-9a-f]{40} Mon Sep 17 00:00:00 2001)\n(From: .+)\n(Date: .+)\nSubject: ([\s\S]+?)(-- \n\d+\.\d+\.\d+\n*)",
    );

    let mut patches = Vec::<Patch>::new();
    let mut line_num = 1;
    for (i, m) in re.find_iter(patch).enumerate() {
        let patch = Patch {
            line_num,
            buf: &m.as_str(),
            ..Default::default()
        };
        patches.push(patch);
        let line_num_next = line_num + m.as_str().matches('\n').count();
        let msg = format!(
            "patch {} (char {}..{}) (line {}-{}) {}",
            i,
            m.start(),
            m.end(),
            line_num,
            line_num_next - 1,
            m.as_str()
        );
        debug!("{}", partial_str(&msg, 80));
        line_num = line_num_next;
    }
    if patches.len() == 0 {
        warn!("no patch found!");
    }
    patches
}

fn convert_patch(formatted_patch: Patch, config: &Config) -> Result<String, String> {
    let re = re(r"^(From [\s\S]+)\n---\n([\s\S]+\d+\.\d+\.\d+\n*)$");
    let captures = match re.captures(formatted_patch.buf) {
        None => {
            let msg = format!("invalid patch (from line {})", formatted_patch.line_num);
            warn!("{}", msg);
            return Err(msg);
        }
        Some(x) => x,
    };
    let mail = captures.get(1).unwrap().as_str();
    let stat_diffs_sign = captures.get(2).unwrap().as_str();
    let line_num_mail = formatted_patch.line_num;
    let line_num_stat_diffs_sign = line_num_mail + mail.matches('\n').count() + 2;

    let mail2 = match config.import_template {
        None => mail.to_string(),
        Some(import_template) => mail_append_import(
            &mail,
            &import_template,
            config.import_sha1_len,
            line_num_mail,
        )?,
    };
    let diff2 =
        replace_stat_diffs_sign(&stat_diffs_sign, &config.replaces, line_num_stat_diffs_sign)?;

    Ok(format!("{}\n---\n{}", mail2, diff2))
}

fn mail_append_import(
    mail: &str,
    import_template: &str,
    mut sha1_len: usize,
    line_num: usize,
) -> Result<String, String> {
    // import_template
    if sha1_len == 0 || sha1_len > 40 {
        warn!("sha1 length must be in 1..40 (given: {})", sha1_len);
        sha1_len = 40;
    }

    let re = re(r"^From ([0-9a-f]{40}) Mon Sep 17 00:00:00 2001$");
    let sha1 = match re.captures(first_line(mail, line_num)?) {
        None => {
            let msg = format!("invalid patch (from line {})", line_num);
            warn!("{}", msg);
            return Err(msg);
        }
        Some(captures) => captures.get(1).unwrap().as_str(),
    };

    let tmp0 = import_template.replace("{}", &sha1[..sha1_len]);
    let mail_last_char = mail
        .chars()
        .last()
        .expect(&format!("invalid patch (from line {})", line_num));
    let tmp = if mail_last_char == '\n' {
        // subject\n(\n---)
        format!("\n{}", tmp0)
    } else {
        // subject\nbody(\n---)
        format!("\n\n{}", tmp0)
    };
    let ret = mail.to_owned() + tmp.as_str();
    Ok(ret)
}

fn replace_stat_diffs_sign(
    stat_diffs_sign: &str,
    replaces: &Vec<(&str, &str)>,
    line_num: usize,
) -> Result<String, String> {
    let re = re(r"^([\s\S]+?\n)(diff --git a/.+ b/.+\n[\s\S]+\n)(-- \n\d+\.\d+\.\d+\n*)$");
    let captures = match re.captures(stat_diffs_sign) {
        None => {
            let msg = format!("invalid patch (from line {})", line_num);
            warn!("{}", msg);
            return Err(msg);
        }
        Some(x) => x,
    };
    let stat = captures.get(1).unwrap().as_str();
    let diffs = captures.get(2).unwrap().as_str();
    let sign = captures.get(3).unwrap().as_str();
    let line_num_stat = line_num;
    let line_num_diffs = line_num_stat + stat.matches('\n').count();
    let line_num_sign = line_num_diffs + diffs.matches('\n').count();

    let msg = format!(
        "stat  (line {}-{}): {}",
        line_num_stat,
        line_num_diffs - 1,
        stat.replace("\n", "\\n"),
    );
    debug!("{}", partial_str(&msg, 80));
    let msg = format!(
        "diffs  (line {}-{}): {}",
        line_num_diffs,
        line_num_sign - 1,
        diffs.replace("\n", "\\n"),
    );
    debug!("{}", partial_str(&msg, 80));
    let msg = format!(
        "sign (line {}-): {}",
        line_num_sign,
        sign.replace("\n", "\\n"),
    );
    debug!("{}", partial_str(&msg, 80));

    let stat2 = replace_stat(stat, replaces, line_num_stat)?;
    let diffs2 = replace_diffs(diffs, replaces, line_num_diffs)?;
    debug!("stat2:  {}", partial_str(&stat2.replace("\n", "\\n"), 80));
    debug!("diffs2: {}", partial_str(&diffs2.replace("\n", "\\n"), 80));

    Ok(stat2 + &diffs2 + sign)
}

fn replace_stat(
    stat: &str,
    replaces: &Vec<(&str, &str)>,
    line_num: usize,
) -> Result<String, String> {
    //  ccc | 1 -
    //  ddd | 0
    //  2 files changed, 1 deletion(-)
    //  delete mode 100644 ccc
    //  create mode 100644 ddd
    let mut ret = String::new();
    for line in stat.lines() {
        if line.contains(" files changed") {
            ret += line;
        } else {
            ret += &replace_vec(line, replaces);
        }
        ret += "\n";
    }
    Ok(ret)
}

fn replace_diffs(
    diffs: &str,
    replaces: &Vec<(&str, &str)>,
    line_num: usize,
) -> Result<String, String> {
    // diff --git a/ccc b/ccc
    // deleted file mode 100644
    // index f2ad6c7..0000000
    // --- a/ccc
    // +++ /dev/null
    // @@ -1 +0,0 @@
    // -ccc
    // diff --git a/ddd b/ddd
    // new file mode 100644
    // index 0000000..e69de29
    let mut ret = String::new();
    for line in diffs.lines() {
        if line.starts_with("diff --git")
            || line.starts_with("--- a/")
            || line.starts_with("+++ b/")
        {
            ret += &replace_vec(line, replaces);
        } else {
            ret += line
        }
        ret += "\n";
    }
    Ok(ret)
}

// -----------------------------------------------------------------------------
// utils

fn first_line(s: &str, line_num: usize) -> Result<&str, String> {
    match s.find("\n") {
        None => {
            let msg = format!("invalid patch (at line {})", line_num);
            warn!("{}", msg);
            return Err(msg);
        }
        Some(x) => Ok(&s[..x]),
    }
}

/// TODO: test
/// partial_str("", 0)  
/// partial_str("a", 0)
/// partial_str("a", 1)  a
/// partial_str("ab", 1)  a
/// partial_str("ab", 2)  ab
/// partial_str("abc", 2)  ab
/// partial_str("abc", 3)  abc
/// partial_str("abcd", 3)  abc
/// partial_str("abcd", 4)  abcd
/// partial_str("abcde", 4)  a...
/// partial_str("abcde", 5)  abcde
/// partial_str("abcdef", 5)  ab...
fn partial_str(s: &str, width: usize) -> String {
    if s.len() <= width {
        return s.to_string();
    }
    if width <= 3 {
        return s[..width].to_string();
    }
    format!("{}...", &s[..(width - 3)]).to_string()
}

// TODO: lazy
fn re(re: &str) -> regex::Regex {
    regex::Regex::new(re).unwrap()
}

fn replace_vec(s: &str, replaces: &Vec<(&str, &str)>) -> String {
    let mut ret = s.to_string();
    for (a, b) in replaces {
        ret = ret.replace(a, b)
    }
    ret
}

// -----------------------------------------------------------------------------
// tests

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let formatted_patch = r#"
From e5e2bbc36649b79f97e165831fe5373c9324bede Mon Sep 17 00:00:00 2001
From: Wataru Ashihara <wataash@wataash.com>
Date: Tue, 24 Mar 2020 21:14:06 +0900
Subject: cccddd TODO: long long long subject wrap

---
 ccc | 1 -
 ddd | 0
 2 files changed, 1 deletion(-)
 delete mode 100644 ccc
 create mode 100644 ddd

diff --git a/ccc b/ccc
deleted file mode 100644
index f2ad6c7..0000000
--- a/ccc
+++ /dev/null
@@ -1 +0,0 @@
-ccc
diff --git a/ddd b/ddd
new file mode 100644
index 0000000..e69de29
-- __EOL__
2.20.1


From e5e2bbc36649b79f97e165831fe5373c9324bede Mon Sep 17 00:00:00 2001
From: Wataru Ashihara <wataash@wataash.com>
Date: Tue, 24 Mar 2020 21:14:06 +0900
Subject: subject

body
---
 ccc | 1 -
 ddd | 0
 2 files changed, 1 deletion(-)
 delete mode 100644 ccc
 create mode 100644 ddd

diff --git a/ccc b/ccc
deleted file mode 100644
index f2ad6c7..0000000
--- a/ccc
+++ /dev/null
@@ -1 +0,0 @@
-ccc
diff --git a/ddd b/ddd
new file mode 100644
index 0000000..e69de29
-- __EOL__
2.20.1


From 54c95b7a05c13730c666209dd1d5d4b9646ab36a Mon Sep 17 00:00:00 2001
From: krw <krw@openbsd.org>
Date: Thu, 5 Jan 2017 12:42:18 +0000
Subject: =?UTF-8?q?Replace=20symset()'s=20hand-rolled=20for(;;)=20traversa?=
 =?UTF-8?q?l=20of=20'symhead'=20TAILQ=0Awith=20more=20modern=20TAILQ=5FFOR?=
 =?UTF-8?q?EACH().=20This=20what=20symget()=20was=20already=0Adoing.?=

Add paranoia '{}' around body of symget()'s TAILQ_FOREACH().

No intentional functional change.

ok bluhm@ otto@
---
 sbin/iked/parse.y | 12 +++++++-----
 1 file changed, 7 insertions(+), 5 deletions(-)

diff --git a/iked/parse.y b/iked/parse.y
index 99880c3f58b..b4168e443a2 100644
--- a/iked/parse.y
+++ b/iked/parse.y
@@ -1,4 +1,4 @@
-/*	$OpenBSD: parse.y,v 1.59 2017/01/04 12:31:01 mikeb Exp $	*/
+/*	$OpenBSD: parse.y,v 1.60 2017/01/05 12:42:18 krw Exp $	*/
 __EOL__
 /*
  * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
@@ -1513,9 +1513,10 @@ symset(const char *nam, const char *val, int persist)
 {
 	struct sym	*sym;
 __EOL__
-	for (sym = TAILQ_FIRST(&symhead); sym && strcmp(nam, sym->nam);
-	    sym = TAILQ_NEXT(sym, entry))
-		;	/* nothing */
+	TAILQ_FOREACH(sym, &symhead, entry) {
+		if (strcmp(nam, sym->nam) == 0)
+			break;
+	}
 __EOL__
 	if (sym != NULL) {
 		if (sym->persist == 1)
@@ -1574,11 +1575,12 @@ symget(const char *nam)
 {
 	struct sym	*sym;
 __EOL__
-	TAILQ_FOREACH(sym, &symhead, entry)
+	TAILQ_FOREACH(sym, &symhead, entry) {
 		if (strcmp(nam, sym->nam) == 0) {
 			sym->used = 1;
 			return (sym->val);
 		}
+	}
 	return (NULL);
 }
 __EOL__
-- __EOL__
2.20.1


From 9f5ef5a99db00059ead4da402bfda7bffc0cb808 Mon Sep 17 00:00:00 2001
From: reyk <reyk@openbsd.org>
Date: Sun, 8 Jan 2017 20:31:03 +0000
Subject: =?UTF-8?q?Sync=20log.c=20with=20the=20latest=20version=20from=20v?=
 =?UTF-8?q?md/log.c=20that=20preserves=20errno=0Aso=20it=20is=20safe=20cal?=
 =?UTF-8?q?ling=20log=5F*=20after=20an=20error=20without=20loosing=20the?=
 =?UTF-8?q?=20it.?=

---
 sbin/iked/log.c | 20 +++++++++++---------
 1 file changed, 11 insertions(+), 9 deletions(-)

diff --git a/iked/log.c b/iked/log.c
index b581ab1b3de..e644eb6c299 100644
--- a/iked/log.c
+++ b/iked/log.c
@@ -1,4 +1,4 @@
-/*	$OpenBSD: log.c,v 1.9 2016/10/12 11:57:31 reyk Exp $	*/
+/*	$OpenBSD: log.c,v 1.10 2017/01/08 20:31:03 reyk Exp $	*/
 __EOL__
 /*
  * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
@@ -90,6 +90,7 @@ void
 vlog(int pri, const char *fmt, va_list ap)
 {
 	char	*nfmt;
+	int	 saved_errno = errno;
 __EOL__
 	if (debug) {
 		/* best effort in out of mem situations */
@@ -103,8 +104,9 @@ vlog(int pri, const char *fmt, va_list ap)
 		fflush(stderr);
 	} else
 		vsyslog(pri, fmt, ap);
-}
 __EOL__
+	errno = saved_errno;
+}
 __EOL__
 void
 log_warn(const char *emsg, ...)
@@ -130,6 +132,8 @@ log_warn(const char *emsg, ...)
 		}
 		va_end(ap);
 	}
+
+	errno = saved_errno;
 }
 __EOL__
 void
@@ -165,11 +169,10 @@ log_debug(const char *emsg, ...)
 }
 __EOL__
 static void
-vfatal(const char *emsg, va_list ap)
+vfatalc(int code, const char *emsg, va_list ap)
 {
 	static char	s[BUFSIZ];
 	const char	*sep;
-	int		 saved_errno = errno;
 __EOL__
 	if (emsg != NULL) {
 		(void)vsnprintf(s, sizeof(s), emsg, ap);
@@ -178,9 +181,9 @@ vfatal(const char *emsg, va_list ap)
 		s[0] = '\0';
 		sep = "";
 	}
-	if (saved_errno)
+	if (code)
 		logit(LOG_CRIT, "%s: %s%s%s",
-		    log_procname, s, sep, strerror(saved_errno));
+		    log_procname, s, sep, strerror(code));
 	else
 		logit(LOG_CRIT, "%s%s%s", log_procname, sep, s);
 }
@@ -191,7 +194,7 @@ fatal(const char *emsg, ...)
 	va_list	ap;
 __EOL__
 	va_start(ap, emsg);
-	vfatal(emsg, ap);
+	vfatalc(errno, emsg, ap);
 	va_end(ap);
 	exit(1);
 }
@@ -201,9 +204,8 @@ fatalx(const char *emsg, ...)
 {
 	va_list	ap;
 __EOL__
-	errno = 0;
 	va_start(ap, emsg);
-	vfatal(emsg, ap);
+	vfatalc(0, emsg, ap);
 	va_end(ap);
 	exit(1);
 }
-- __EOL__
2.20.1


From 4ff7cad5c173774706eddccb3a70ba75a37073dd Mon Sep 17 00:00:00 2001
From: krw <krw@openbsd.org>
Date: Mon, 9 Jan 2017 14:04:31 +0000
Subject: =?UTF-8?q?Replace=20hand-rolled=20for(;;)=20traversal=20of=20ctl?=
 =?UTF-8?q?=5Fconns=20TAILQ=20with=0ATAILQ=5FFOREACH().?=

No intentional functional change.

ok reyk@

Imported from: https://github.com/openbsd/src/commit/4ff7cad5c173
---
 sbin/iked/control.c | 9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

diff --git a/iked/control.c b/iked/control.c
index 94f4dbc7329..ed8713716db 100644
--- a/iked/control.c
+++ b/iked/control.c
@@ -1,4 +1,4 @@
-/*	$OpenBSD: control.c,v 1.22 2016/09/04 16:55:43 reyk Exp $	*/
+/*	$OpenBSD: control.c,v 1.23 2017/01/09 14:04:31 krw Exp $	*/
 __EOL__
 /*
  * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
@@ -215,9 +215,10 @@ control_connbyfd(int fd)
 {
 	struct ctl_conn	*c;
 __EOL__
-	for (c = TAILQ_FIRST(&ctl_conns); c != NULL && c->iev.ibuf.fd != fd;
-	    c = TAILQ_NEXT(c, entry))
-		;	/* nothing */
+	TAILQ_FOREACH(c, &ctl_conns, entry) {
+		if (c->iev.ibuf.fd == fd)
+			break;
+	}
 __EOL__
 	return (c);
 }
-- __EOL__
2.20.1"#;
        let formatted_patch = formatted_patch.replace("__EOL__", "");
        let formatted_patch = formatted_patch.as_str();

        let config = super::Config {
            replaces: vec![
                //
                ("sbin/iked/", "iked/"),
                ("usr.sbin/ikectl/", "ikectl/"),
            ],
            import_template: Some("Imported from: https://github.com/openbsd/src/commit/{}"),
            import_sha1_len: 12,
        };
        let patches2 = super::convert_formatted_patch(formatted_patch, &config);
        print!("{}", patches2);
        let _breakpoint = 1;
    }

    #[test]
    fn exploration() {
        assert_eq!(2 + 2, 4);
    }
}
