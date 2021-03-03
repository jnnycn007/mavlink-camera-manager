use crate::settings;
use crate::stream;

use crate::video::{
    types::*,
    video_source::VideoSource,
    video_source_local::{UsbBus, VideoSourceLocalType},
};
use crate::video_stream::types::VideoAndStreamInformation;

use log::*;

pub fn run() {
    settings::manager::init(None);
    let mut streams = settings::manager::streams();

    // Update all local video sources to make sure that is available
    streams.iter_mut().for_each(|stream| {
        if let VideoSourceType::Local(source) = &mut stream.video_source {
            if !source.update_device() {
                error!("Source appears to be invalid or not found: {:#?}", source);
            }
        }
    });

    // Remove all invalid video_sources
    let streams: Vec<VideoAndStreamInformation> = streams
        .into_iter()
        .filter(|stream| stream.video_source.inner().is_valid())
        .map(Into::into)
        .collect();

    println!("streams: {:#?}", streams);

    for stream in streams {
        stream::manager::add_stream_and_start(stream);
    }
}
