import { NextResponse, NextRequest } from "next/server";
import { sunoApi, sunoApiNoInit } from "@/lib/SunoApi";
import { corsHeaders, sleep } from "@/lib/utils";
import { get } from "http";
import { getRedisInstance } from "@/lib/redis";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  if (req.method === 'GET') {
    try {
      const url = new URL(req.url);
      // const clipId = url.searchParams.get('id');
      // if (clipId == null) {
      //   return new NextResponse(JSON.stringify({ error: 'Missing parameter id' }), {
      //     status: 400,
      //     headers: {
      //       'Content-Type': 'application/json',
      //       ...corsHeaders
      //     }
      //   });
      // }

      // const redisInstance = getRedisInstance();
      // console.log(await redisInstance.get('captcha_v2_token'));
      //   await redisInstance.set('captcha_v2_token','9999999');
      // console.log(await redisInstance.get('captcha_v2_token'));
      // return;

      (await sunoApiNoInit()).getCaptchaV2();

      return new NextResponse('{}', {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    } catch (error) {
      return new NextResponse(JSON.stringify({ error: 'Internal server error' }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
} else if (req.method === 'POST') {
    console.log('重置浏览器模拟器状态...');
    process.env.SIMULATE_BROWSER_FOR_TOKEN_STATS = '1';
    process.env.SIMULATE_BROWSER_FOR_TOKEN_START = '1';
    console.log('浏览器模拟器状态已重置。');
    return new NextResponse('{}', {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  } else {
    return new NextResponse('Method Not Allowed', {
      headers: {
        Allow: 'GET/POST',
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