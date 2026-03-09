import { GoogleGenAI } from "@google/genai";
import { Buffer } from "buffer";
import fs from "fs";

const client = new GoogleGenAI({
  apiKey: process.env.GOOGLE_GENAI_API_KEY || "",
  apiVersion: "v1alpha" ,
});

async function lyriaRealtime(textPrompt: string) {
  // const speaker = new Speaker({
  //   channels: 2,       // stereo
  //   bitDepth: 16,      // 16-bit PCM
  //   sampleRate: 44100, // 44.1 kHz
  // });

  // 结束标志
  let isFinished = false;

  const session = await client.live.music.connect({
    model: "models/lyria-realtime-exp",
    callbacks: {
      onmessage: (message) => {
        console.log("Received message:", message);
        if (message.serverContent?.audioChunks) {
          for (const chunk of message.serverContent.audioChunks) {
            const mt = chunk.mimeType; 
            console.log("Received audio chunk with MIME type:", mt);
            if (chunk.data) {
              console.log("Chunk data length (base64):", chunk.data.length);
              const audioBuffer = Buffer.from(chunk.data, "base64");
              fs.writeFileSync("/tmp/output.raw", audioBuffer); // Save raw audio for debugging
            }
            // speaker.write(audioBuffer);
          }
        }
      },
      onerror: (error) => console.error("music session error:", error),
      onclose: () => {
        console.log("Music session closed");
        isFinished = true;
      },
    },
  });

  await session.setWeightedPrompts({
    weightedPrompts: [
      { text: textPrompt, weight: 1.0 },
    ],
  });

  await session.setMusicGenerationConfig({
    musicGenerationConfig: {
      bpm: 90,
      temperature: 1.0,
      // audioFormat: "pcm16",  // important so we know format
      // sampleRateHz: 44100,
    },
  });

  session.play();

  // 等待生成完成或设置超时
    await new Promise((resolve) => {
        const checkInterval = setInterval(() => {
            if (isFinished) {
                clearInterval(checkInterval);
                resolve(null);
            }
        }, 1000); // 每秒检查一次
    });

  console.log("Music generation session ended");
}

export { lyriaRealtime };