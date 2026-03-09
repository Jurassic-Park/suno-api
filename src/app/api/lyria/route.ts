import { NextResponse, NextRequest } from "next/server";
import { corsHeaders } from "@/lib/utils";
import fs from "fs";
import { GoogleGenAI } from "@google/genai";
import { Buffer } from "buffer";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  if (req.method === 'POST') {
    try {
      const body = await req.json();
      const { prompt } = body;

      const client = new GoogleGenAI({
        apiKey: process.env.GOOGLE_GENAI_API_KEY || "",
        apiVersion: "v1alpha" ,
      });

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
                  fs.writeFileSync("output.raw", audioBuffer); // Save raw audio for debugging
                }
                // speaker.write(audioBuffer);
              }
            }
          },
          onerror: (error) => console.error("music session error:", error),
          onclose: () => console.log("Lyria RealTime stream closed."),
        },
      });

      await session.setWeightedPrompts({
        weightedPrompts: [
          { text: prompt, weight: 1.0 },
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
      
      try {
        // Wait for the session to complete or set a timeout
        await new Promise((resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error("Music generation timed out"));
          }, 60000); // 60 seconds timeout
        });
      } catch (error) {
        console.error('Error during music generation:', error);
      }


      return new NextResponse(JSON.stringify({ message: "Audio generated successfully" }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    } catch (error: any) {
      console.error('Error upload:', error);
      return new NextResponse(JSON.stringify({ error: 'Internal server error: ' + error }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
  }
}

export async function GET(req: Request) {
    // 反回文件流
    const url = new URL(req.url);
    const filename = url.searchParams.get('filename');
    if (!filename) {
      return new NextResponse(JSON.stringify({ error: 'Filename is required' }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }

    const filePath = `./output.raw`; // Assuming the file is saved as output.raw
    try {
      const fileBuffer = await fs.promises.readFile(filePath);
      const body = new Uint8Array(fileBuffer);
      return new NextResponse(body, {
        status: 200,
        headers: {
          'Content-Type': 'audio/wav', // Adjust based on actual format
          'Content-Disposition': `attachment; filename="${filename}"`,
          ...corsHeaders
        }
      });
    } catch (error) {
      console.error('Error reading file:', error);
      return new NextResponse(JSON.stringify({ error: 'File not found' }), {
        status: 404,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
}

export async function OPTIONS(request: Request) {
  return new Response(null, {
    status: 200,
    headers: corsHeaders
  });
}