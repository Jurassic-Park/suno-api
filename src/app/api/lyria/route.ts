import { NextResponse, NextRequest } from "next/server";
import { corsHeaders } from "@/lib/utils";
import fs from "fs";
import { lyriaRealtime } from "@/lib/googleGenai";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
    try {
      const body = await req.json();
      const { prompt } = body;

      lyriaRealtime(prompt).catch(console.error);

      console.log("Music generation started with prompt:", prompt);
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
    } catch (error) {
      console.error('Error processing request:', error);
      return new NextResponse(JSON.stringify({ error: 'Internal Server Error' }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
}

export async function GET(req: Request) {
    fs.writeFileSync("/tmp/output.raw", "999999999999"); // Save raw audio for debugging
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