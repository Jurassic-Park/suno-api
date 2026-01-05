import { NextResponse, NextRequest } from "next/server";
import { cookies } from 'next/headers'
import { DEFAULT_MODEL, sunoApi } from "@/lib/SunoApi";
import { corsHeaders } from "@/lib/utils";
import pino from 'pino';

const logger = pino();
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  if (req.method === 'POST') {
    try {
      const body = await req.json();
      const { prompt, make_instrumental, model, wait_audio, cover_clip_id } = body;

      const audioInfo = await (await sunoApi((await cookies()).toString())).generate(
        prompt,
        Boolean(make_instrumental),
        model || DEFAULT_MODEL,
        Boolean(wait_audio),
        cover_clip_id
      );

      return new NextResponse(JSON.stringify(audioInfo), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    } catch (error: any) {
      console.error('Error generating audio:', error);
      if (error.response.status === 402) {
        return new NextResponse(JSON.stringify({ error: error.response.data.detail }), {
          status: 402,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders
          }
        });
      }

      if (error.message?.includes('CAPTCHA')) {
        return new NextResponse(JSON.stringify({
          error: 'CAPTCHA verification failed',
          code: 'CAPTCHA_FAILED',
          details: error.message
        }), {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders
          }
        });
      }

      // Browser/automation related errors
      if (error.message?.includes('browser') || error.message?.includes('chrome') || error.message?.includes('executable')) {
        return new NextResponse(JSON.stringify({
          error: 'Browser automation error',
          code: 'BROWSER_ERROR',
          details: error.message
        }), {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders
          }
        });
      }

      // Generic error response
      return new NextResponse(JSON.stringify({
        error: 'Internal server error',
        code: 'INTERNAL_ERROR',
        details: error.message || 'Unknown error occurred',
        errorObject: JSON.stringify(error, Object.getOwnPropertyNames(error))
      }), {

        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
  } else {
    return new NextResponse('Method Not Allowed', {
      headers: {
        Allow: 'POST',
        ...corsHeaders
      },
      status: 405
    });
  }
}


export async function OPTIONS(request: Request) {
  return new Response(null, {
    status: 200,
    headers: corsHeaders
  });
}