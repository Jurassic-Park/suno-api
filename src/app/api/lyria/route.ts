import { NextResponse, NextRequest } from "next/server";
import { cookies } from 'next/headers'
import { DEFAULT_MODEL, sunoApi } from "@/lib/SunoApi";
import { corsHeaders } from "@/lib/utils";
import { lyriaRealtime } from "@/lib/googleGenai";
import fs from "fs";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  if (req.method === 'POST') {
    try {
      const body = await req.json();
      const { prompt } = body;

      await lyriaRealtime(prompt);

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
  } else {
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
}


export async function OPTIONS(request: Request) {
  return new Response(null, {
    status: 200,
    headers: corsHeaders
  });
}