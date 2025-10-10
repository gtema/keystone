use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use openstack_keystone::config::Config;
use openstack_keystone::token::fernet::FernetTokenProvider;
use openstack_keystone::token::types::TokenBackend;

fn decode(backend: &FernetTokenProvider, token: &str) {
    backend.decrypt(token).unwrap();
}

fn bench_decrypt_token(c: &mut Criterion) {
    let tmp_dir = tempdir().unwrap();
    // write fernet key used to generate tokens in python
    let file_path = tmp_dir.path().join("0");
    let mut tmp_file = File::create(file_path).unwrap();
    write!(tmp_file, "BFTs1CIVIBLTP4GOrQ26VETrJ7Zwz1O4wbEcCQ966eM=").unwrap();

    let builder = config::Config::builder()
        .set_override("auth.methods", "password,token")
        .unwrap()
        .set_override("database.connection", "dummy")
        .unwrap();
    let mut config: Config = Config::try_from(builder).expect("can build a valid config");
    let mut backend = FernetTokenProvider::default();

    config.fernet_tokens.key_repository = tmp_dir.keep();
    backend.set_config(config);
    backend.load_keys().unwrap();

    let token = "gAAAAABns2ixy75K_KfoosWLrNNqG6KW8nm3Xzv0_2dOx8ODWH7B8i2g8CncGLO6XBEH_TYLg83P6XoKQ5bU8An8Kqgw9WX3bvmEQXphnwPM6aRAOQUSdVhTlUm_8otDG9BS2rc70Q7pfy57S3_yBgimy-174aKdP8LPusvdHZsQPEJO9pfeXWw";

    c.bench_with_input(
        BenchmarkId::new("fernet token", "project"),
        &(backend, token),
        |b, (backend, s)| {
            b.iter(|| decode(backend, s));
        },
    );
}

criterion_group!(benches, bench_decrypt_token);
criterion_main!(benches);
