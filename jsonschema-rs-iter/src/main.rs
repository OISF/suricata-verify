use std::{error::Error, fs, path::PathBuf, process};

use jsonschema::JSONSchema;
use structopt::StructOpt;

type BoxErrorResult<T> = Result<T, Box<dyn Error>>;

use std::fs::File;
use std::io::BufReader;

#[derive(Debug, StructOpt)]
#[structopt(name = "jsonschema")]
struct Cli {
    /// A path to a JSON instance (i.e. filename.json) to validate (may be specified multiple times).
    #[structopt(short = "i", long = "instance")]
    instances: Option<Vec<PathBuf>>,

    /// The JSON Schema to validate with (i.e. schema.json).
    #[structopt(parse(from_os_str), required_unless("version"))]
    schema: Option<PathBuf>,

    /// Show program's version number and exit.
    #[structopt(short = "v", long = "version")]
    version: bool,
}

pub fn main() -> BoxErrorResult<()> {
    let config = Cli::from_args();

    if config.version {
        println!("Version: {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let mut success = true;
    if let Some(schema) = config.schema {
        if let Some(instances) = config.instances {
            success = validate_instances(&instances, schema)?;
        }
    }

    if !success {
        process::exit(1);
    }

    Ok(())
}

fn validate_instances(instances: &[PathBuf], schema: PathBuf) -> BoxErrorResult<bool> {
    let mut success = true;

    let schema_json = fs::read_to_string(schema)?;
    let schema_json = serde_json::from_str(&schema_json)?;
    match JSONSchema::compile(&schema_json) {
        Ok(schema) => {
            for instance in instances {
                let instance_path_name = instance.to_str().unwrap();
                let file = File::open(instance_path_name)?;
                let reader = BufReader::new(file);
                let deserializer = serde_json::Deserializer::from_reader(reader);
                let iterator = deserializer.into_iter::<serde_json::Value>();
                let mut success_i = true;
                for item in iterator {
                    let instance_json = item?;
                    let validation = schema.validate(&instance_json);
                    match validation {
                        Ok(_) => {}
                        Err(errors) => {
                            success = false;
                            success_i = false;
                            println!("{} - INVALID. Errors:", instance_path_name);
                            for (i, e) in errors.enumerate() {
                                println!("{}.{} {}", i + 1, e.instance_path, e);
                            }
                        }
                    }
                }
                if success_i {
                    println!("{} - VALID", instance_path_name);
                }
            }
        }
        Err(error) => {
            println!("Schema is invalid. Error: {}", error);
            success = false;
        }
    }
    Ok(success)
}
