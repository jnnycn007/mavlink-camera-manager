use crate::{
    stream::types::CaptureConfiguration,
    video::types::{VideoEncodeType, VideoSourceType},
    video_stream::types::VideoAndStreamInformation,
};

use super::{
    PipelineGstreamerInterface, PipelineState, PIPELINE_FILTER_NAME, PIPELINE_SINK_TEE_NAME,
};

use anyhow::{anyhow, Result};

use tracing::*;

use gst::prelude::*;

#[derive(Debug)]
pub struct V4lPipeline {
    pub state: PipelineState,
}

impl V4lPipeline {
    #[instrument(level = "debug")]
    pub fn try_new(
        pipeline_id: uuid::Uuid,
        video_and_stream_information: &VideoAndStreamInformation,
    ) -> Result<gst::Pipeline> {
        let configuration = match &video_and_stream_information
            .stream_information
            .configuration
        {
            CaptureConfiguration::Video(configuration) => configuration,
            unsupported => return Err(anyhow!("{unsupported:?} is not supported as V4l Pipeline")),
        };

        let video_source = match &video_and_stream_information.video_source {
            VideoSourceType::Local(source) => source,
            unsupported => {
                return Err(anyhow!(
                    "SourceType {unsupported:?} is not supported as V4l Pipeline"
                ))
            }
        };

        let device = video_source.device_path.as_str();
        let width = configuration.width;
        let height = configuration.height;
        let interval_numerator = configuration.frame_interval.numerator;
        let interval_denominator = configuration.frame_interval.denominator;

        let description = match &configuration.encode {
            VideoEncodeType::H264 => {
                format!(
                    concat!(
                        "v4l2src device={device} do-timestamp=false",
                        " ! h264parse",
                        " ! capsfilter name={filter_name} caps=video/x-h264,stream-format=avc,alignment=au,width={width},height={height},framerate={interval_denominator}/{interval_numerator}",
                        " ! rtph264pay aggregate-mode=zero-latency config-interval=10 pt=96",
                        " ! tee name={sink_tee_name} allow-not-linked=true"
                    ),
                    device = device,
                    width = width,
                    height = height,
                    interval_denominator = interval_denominator,
                    interval_numerator = interval_numerator,
                    filter_name = format!("{PIPELINE_FILTER_NAME}-{pipeline_id}"),
                    sink_tee_name = format!("{PIPELINE_SINK_TEE_NAME}-{pipeline_id}"),
                )
            }
            VideoEncodeType::Yuyv => {
                format!(
                    concat!(
                        "v4l2src device={device} do-timestamp=false",
                        " ! videoconvert",
                        " ! capsfilter name={filter_name} caps=video/x-raw,format=I420,width={width},height={height},framerate={interval_denominator}/{interval_numerator}",
                        " ! rtpvrawpay pt=96",
                        " ! tee name={sink_tee_name} allow-not-linked=true"
                    ),
                    device = device,
                    width = width,
                    height = height,
                    interval_denominator = interval_denominator,
                    interval_numerator = interval_numerator,
                    filter_name = format!("{PIPELINE_FILTER_NAME}-{pipeline_id}"),
                    sink_tee_name = format!("{PIPELINE_SINK_TEE_NAME}-{pipeline_id}"),
                )
            }
            VideoEncodeType::Mjpg => {
                format!(
                    concat!(
                        "v4l2src device={device} do-timestamp=false",
                        // We don't need a jpegparse, as it leads to incompatible caps, spoiling the negotiation.
                        " ! capsfilter name={filter_name} caps=image/jpeg,width={width},height={height},framerate={interval_denominator}/{interval_numerator}",
                        " ! rtpjpegpay pt=96",
                        " ! tee name={sink_tee_name} allow-not-linked=true"
                    ),
                    device = device,
                    width = width,
                    height = height,
                    interval_denominator = interval_denominator,
                    interval_numerator = interval_numerator,
                    filter_name = format!("{PIPELINE_FILTER_NAME}-{pipeline_id}"),
                    sink_tee_name = format!("{PIPELINE_SINK_TEE_NAME}-{pipeline_id}"),
                )
            }
            unsupported => {
                return Err(anyhow!(
                    "Encode {unsupported:?} is not supported for V4L2 Pipeline"
                ))
            }
        };

        debug!("pipeline_description: {description:#?}");

        let pipeline = gst::parse_launch(&description)?;

        let pipeline = pipeline
            .downcast::<gst::Pipeline>()
            .expect("Couldn't downcast pipeline");

        Ok(pipeline)
    }
}

impl PipelineGstreamerInterface for V4lPipeline {
    #[instrument(level = "trace")]
    fn is_running(&self) -> bool {
        self.state.pipeline_runner.is_running()
    }
}
