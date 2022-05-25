use std::{error::Error, fs, path::PathBuf, process};

use clap::Parser;
use jsonschema::JSONSchema;

type BoxErrorResult<T> = Result<T, Box<dyn Error>>;

use std::fs::File;
use std::io::BufReader;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// A path to a JSON instance (i.e. filename.json) to validate (may be specified multiple times).
    #[clap(last = true)]
    instances: Vec<PathBuf>,

    /// The JSON Schema to validate with (i.e. schema.json).
    #[clap(short, long)]
    schema: PathBuf,

    /// Quiet output
    #[clap(short, long)]
    quiet: bool,
}

pub fn main() -> BoxErrorResult<()> {
    let config = Cli::parse();

    let success = validate_instances(&config.instances, config.schema, config.quiet)?;

    if !success {
        process::exit(1);
    }

    Ok(())
}

fn validate_instances(instances: &[PathBuf], schema: PathBuf, quiet: bool) -> BoxErrorResult<bool> {
    let mut success = true;

    let schema_json = fs::read_to_string(&schema).map_err(|err| {
        format!("Failed to read {}: {:?}", schema.display(), err)
    })?;
    let schema_json = serde_json::from_str(&schema_json).map_err(|err| {
        format!("Failed to parse {}: {:?}", schema.display(), err)
    })?;
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
                if success_i && !quiet {
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
