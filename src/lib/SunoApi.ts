import axios, { AxiosInstance } from 'axios';
import UserAgent from 'user-agents';
import pino from 'pino';
import yn from 'yn';
import { base64ToFile, isPage, sleep, waitForRequests } from '@/lib/utils';
import * as cookie from 'cookie';
import { randomUUID } from 'node:crypto';
import { Solver } from '@2captcha/captcha-solver';
import chromium from '@sparticuz/chromium';
import { paramsCoordinates } from '@2captcha/captcha-solver/dist/structs/2captcha';
import type { BrowserContext, Page, Locator } from 'rebrowser-playwright-core';
import * as playwright from 'rebrowser-playwright-core';
import { createCursor, Cursor } from 'ghost-cursor-playwright';
import { promises as fs } from 'fs';
import path from 'node:path';
import uniq from 'lodash.uniq';

// sunoApi instance caching
const globalForSunoApi = global as unknown as {
  sunoApiCache?: Map<string, SunoApi>;
};

const cache = globalForSunoApi.sunoApiCache || new Map<string, SunoApi>();
globalForSunoApi.sunoApiCache = cache;

const logger = pino();
// export const DEFAULT_MODEL = 'chirp-v3-5';
export const DEFAULT_MODEL = 'chirp-auk-turbo';

export interface AudioInfo {
  id: string; // Unique identifier for the audio
  title?: string; // Title of the audio
  image_url?: string; // URL of the image associated with the audio
  lyric?: string; // Lyrics of the audio
  audio_url?: string; // URL of the audio file
  video_url?: string; // URL of the video associated with the audio
  created_at: string; // Date and time when the audio was created
  model_name: string; // Name of the model used for audio generation
  gpt_description_prompt?: string; // Prompt for GPT description
  prompt?: string; // Prompt for audio generation
  status: string; // Status
  type?: string;
  tags?: string; // Genre of music.
  negative_tags?: string; // Negative tags of music.
  duration?: string; // Duration of the audio
  error_message?: string; // Error message if any
}

interface PersonaResponse {
  persona: {
    id: string;
    name: string;
    description: string;
    image_s3_id: string;
    root_clip_id: string;
    clip: any; // You can define a more specific type if needed
    user_display_name: string;
    user_handle: string;
    user_image_url: string;
    persona_clips: Array<{
      clip: any; // You can define a more specific type if needed
    }>;
    is_suno_persona: boolean;
    is_trashed: boolean;
    is_owned: boolean;
    is_public: boolean;
    is_public_approved: boolean;
    is_loved: boolean;
    upvote_count: number;
    clip_count: number;
  };
  total_results: number;
  current_page: number;
  is_following: boolean;
}

class SunoApi {
  private static BASE_URL: string = 'https://studio-api.prod.suno.com';
  private static CLERK_BASE_URL: string = 'https://auth.suno.com';
  // private static BASE_URL: string = 'http://127.0.0.1:8080/suno.com-api';
  // private static CLERK_BASE_URL: string = 'http://127.0.0.1:8080/suno.com-auth-api';
  private static CLERK_VERSION = '5.117.0';

  private readonly client: AxiosInstance;
  private sid?: string;
  private currentToken?: string;
  private deviceId?: string;
  private isVercel: boolean;
  private userAgent?: string;
  private cookies: Record<string, string | undefined>;
  private solver = new Solver(process.env.TWOCAPTCHA_KEY + '');
  private ghostCursorEnabled = yn(process.env.BROWSER_GHOST_CURSOR, {
    default: false
  });
  private cursor?: Cursor;
  
  constructor(cookies: string) {
    this.isVercel = process.env.VERCEL_URL !== undefined;
    this.userAgent = new UserAgent(/Macintosh/).random().toString(); // Usually Mac systems get less amount of CAPTCHAs
    this.cookies = cookie.parse(cookies);
    this.deviceId = this.cookies.ajs_anonymous_id || randomUUID();
    this.client = axios.create({
      withCredentials: true,
      headers: {
        'Affiliate-Id': 'undefined',
        'Device-Id': `"${this.deviceId}"`,
        'x-suno-client': 'Android prerelease-4nt180t 1.0.42',
        'X-Requested-With': 'com.suno.android',
        'sec-ch-ua': '"Chromium";v="130", "Android WebView";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'User-Agent': this.userAgent
      }
    });
    this.client.interceptors.request.use(config => {
      // 请求链接包含suno.com时，添加Authorization头
      if (config.url?.includes('suno.com') && this.currentToken && this.currentToken != undefined && !config.headers.Authorization)
        config.headers.Authorization = `Bearer ${this.currentToken}`;
      const cookiesArray = Object.entries(this.cookies).map(([key, value]) =>
        cookie.serialize(key, value as string)
      );
      config.headers.Cookie = cookiesArray.join('; ');
      return config;
    });
    this.client.interceptors.response.use((resp) => {
      const setCookieHeader = resp.headers['set-cookie'];
      if (Array.isArray(setCookieHeader)) {
        const newCookies = cookie.parse(setCookieHeader.join('; '));
        for (const [key, value] of Object.entries(newCookies)) {
          this.cookies[key] = value;
        }
      }
      return resp;
    });
  }

  public async init(): Promise<SunoApi> {
    //await this.getClerkLatestVersion();
    await this.getAuthToken();
    await this.keepAlive();
    return this;
  }

  /**
   * Get the clerk package latest version id.
   * This method is commented because we are now using a hard-coded Clerk version, hence this method is not needed.
   
  private async getClerkLatestVersion() {
    // URL to get clerk version ID
    const getClerkVersionUrl = `${SunoApi.JSDELIVR_BASE_URL}/v1/package/npm/@clerk/clerk-js`;
    // Get clerk version ID
    const versionListResponse = await this.client.get(getClerkVersionUrl);
    if (!versionListResponse?.data?.['tags']['latest']) {
      throw new Error(
        'Failed to get clerk version info, Please try again later'
      );
    }
    // Save clerk version ID for auth
    SunoApi.clerkVersion = versionListResponse?.data?.['tags']['latest'];
  }
  */

  /**
   * Get the session ID and save it for later use.
   */
  private async getAuthToken() {
    // this.sid = "session_b2fcd20cedcd920400959d"
    // this.currentToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdW5vLmNvbS9jbGFpbXMvdXNlcl9pZCI6IjM0N2RhM2FhLWNiYTQtNGU4MS05NjVjLTkzZmQ1NWM2ODg3NyIsImh0dHBzOi8vc3Vuby5haS9jbGFpbXMvY2xlcmtfaWQiOiJ1c2VyXzM2RVpQdEhhellNbzMyRlVFaHVKTnROUDhLdyIsInN1bm8uY29tL2NsYWltcy90b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzY3Njg4MzY5LCJhdWQiOiJzdW5vLWFwaSIsInN1YiI6InVzZXJfMzZFWlB0SGF6WU1vMzJGVUVodUpOdE5QOEt3IiwiYXpwIjoiaHR0cHM6Ly9zdW5vLmNvbSIsImZ2YSI6WzAsLTFdLCJpYXQiOjE3Njc2ODQ3NjksImlzcyI6Imh0dHBzOi8vYXV0aC5zdW5vLmNvbSIsImppdCI6IjNjNWUwMWE4LWExNjMtNGIyMC04ZmEwLWQwOWI1MjE0MzA0MSIsInZpeiI6ZmFsc2UsInNpZCI6InNlc3Npb25fYjJmY2QyMGNlZGNkOTIwNDAwOTU5ZCIsInN1bm8uY29tL2NsYWltcy9lbWFpbCI6IjM0MzY1MTE1MkBxcS5jb20iLCJodHRwczovL3N1bm8uYWkvY2xhaW1zL2VtYWlsIjoiMzQzNjUxMTUyQHFxLmNvbSJ9.qtQMKnmr7sOq4g8CoowJlX12ltD88oSJ6YkDG-LRnBQMuo8Vccnp1k31paC2FCyA0UhbXda8Hq1VI0FJsclDoCy03yupubbXr9J6XNeVdiFv1_801HZxcSrns-hzl5_2ugKCN6877jPGxiuKUNvs2YTceA4RNnFjjeuZR2WHxzCofTk9l1qRnvLiyxOwMjHhSSIQR7Exn9FrqZgxmdN_TDQy3pjXSq6HUQYkbeKRlvulbmtEb_H3eT1zc2gSlSbR3w08bmxYzVwJRsWNw1YCYdNzVM6SFLR7tsyZajjCDuBuR72feJtGjKwugc--WYcPbLVAzzgoT8mHdC7NPJW3vw'

    logger.info('Getting the session ID');
    // URL to get session ID
    const getSessionUrl = `${SunoApi.CLERK_BASE_URL}/v1/client?__clerk_api_version=2025-11-10&_clerk_js_version=${SunoApi.CLERK_VERSION}`;
    // console.error(getSessionUrl, this.cookies.__client,"99999");
    // Get session ID
    const sessionResponse = await this.client.get(getSessionUrl, {
       headers: { Authorization: this.cookies.__client }
    });
    if (!sessionResponse?.data?.response?.last_active_session_id) {
      console.error("Session Error Response:", JSON.stringify(sessionResponse.data));
      throw new Error(
        'Failed to get session id, you may need to update the SUNO_COOKIE'
      );
    }
    // Save session ID for later use
    this.sid = sessionResponse.data.response.last_active_session_id;
    this.currentToken = sessionResponse.data.response.sessions[0].last_active_token.jwt;
  }

  /**
   * Keep the session alive.
   * @param isWait Indicates if the method should wait for the session to be fully renewed before returning.
   */
  public async keepAlive(isWait?: boolean): Promise<void> {
    if (!this.sid) {
      throw new Error('Session ID is not set. Cannot renew token.');
    }
    // URL to renew session token
    const renewUrl = `${SunoApi.CLERK_BASE_URL}/v1/client/sessions/${this.sid}/touch?__clerk_api_version=2025-11-10&_clerk_js_version=${SunoApi.CLERK_VERSION}`;
    // Renew session token
    logger.info('KeepAlive... '+renewUrl+' \n');
    const renewResponse = await this.client.post(renewUrl, {}, {
      // headers: { Authorization: this.cookies.__client }
    });

    // logger.info('Renew Response:\n' + JSON.stringify(renewResponse.data, null, 2));
    if (isWait) {
      await sleep(1, 2);
    }
    const newToken = renewResponse.data.response.last_active_token.jwt;
    // Update Authorization field in request header with the new JWT token
    this.currentToken = newToken;
  }

  /**
   * Get the session token (not to be confused with session ID) and save it for later use.
   */
  private async getSessionToken() {
    const tokenResponse = await this.client.post(
      `${SunoApi.BASE_URL}/api/user/create_session_id/`,
      {
        session_properties: JSON.stringify({ deviceId: this.deviceId }),
        session_type: 1
      }
    );
    return tokenResponse.data.session_id;
  }

  private async captchaRequired(): Promise<boolean> {
    const resp = await this.client.post(`${SunoApi.BASE_URL}/api/c/check`, {
      ctype: 'generation'
    });
    logger.info(resp.data);
    return resp.data.required;
  }

  /**
   * Clicks on a locator or XY vector. This method is made because of the difference between ghost-cursor-playwright and Playwright methods
   */
  private async click(target: Locator|Page, position?: { x: number, y: number }): Promise<void> {
    if (this.ghostCursorEnabled) {
      let pos: any = isPage(target) ? { x: 0, y: 0 } : await target.boundingBox();
      if (position) 
        pos = {
          ...pos,
          x: pos.x + position.x,
          y: pos.y + position.y,
          width: null,
          height: null,
        };
      return this.cursor?.actions.click({
        target: pos
      });
    } else {
      if (isPage(target))
        return target.mouse.click(position?.x ?? 0, position?.y ?? 0);
      else
        return target.click({ force: true, position });
    }
  }

  /**
   * Get the BrowserType from the `BROWSER` environment variable.
   * @returns {BrowserType} chromium, firefox or webkit. Default is chromium
   */
  private getBrowserType() {
    const browser = process.env.BROWSER?.toLowerCase();
    switch (browser) {
      case 'firefox':
        return playwright.firefox;
      default:
        return playwright.chromium;
    }
  }

  /**
   * Launches a browser with the necessary cookies
   * @returns {BrowserContext}
   */
  private async launchBrowser(): Promise<BrowserContext> {
    let baseArgs = [
      '--disable-blink-features=AutomationControlled',
      '--disable-web-security',
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-features=site-per-process',
      '--disable-features=IsolateOrigins',
      '--disable-extensions'
    ];
    // Check for GPU acceleration, as it is recommended to turn it off for Docker
    if (yn(process.env.BROWSER_DISABLE_GPU, { default: false }))

    baseArgs.push(
      '--enable-unsafe-swiftshader',
      '--disable-gpu',
      '--disable-setuid-sandbox'
    );

    logger.info({
      msg: 'Launching browser',
      isVercel: this.isVercel,
      nodeEnv: process.env.NODE_ENV,
      totalArgs: baseArgs.length
    });

    let browser: playwright.Browser;

    if (this.isVercel) {
      browser = await playwright.chromium.launch({
        args: uniq([...baseArgs, ...chromium.args]),
        executablePath: await chromium.executablePath(),
        headless: true
      });
    } else {
      browser = await this.getBrowserType().launch({
        args: baseArgs,
        headless: yn(process.env.BROWSER_HEADLESS, { default: true })
      });
    }

    const context = await browser.newContext({
      userAgent: this.userAgent,
      locale: process.env.BROWSER_LOCALE,
      viewport: null
    });

    const cookies = [];
    const lax: 'Lax' | 'Strict' | 'None' = 'Lax';
    cookies.push({
      name: '__session',
      value: this.currentToken+'',
      domain: '.suno.com',
      path: '/',
      sameSite: lax
    });
    for (const key in this.cookies) {
      cookies.push({
        name: key,
        value: this.cookies[key]+'',
        domain: '.suno.com',
        path: '/',
        sameSite: lax
      })
    }
    await context.addCookies(cookies);
    return context;
  }

  /**
   * Checks for CAPTCHA verification and solves the CAPTCHA if needed
   * @returns {string|null} hCaptcha token. If no verification is required, returns null
   */
  public async getCaptcha(): Promise<string|null> {
    return null;
    if (!await this.captchaRequired())
      return null;

    logger.info('CAPTCHA required. Launching browser...')
    const browser = await this.launchBrowser();
    const page = await browser.newPage();
    await page.goto('https://suno.com/create', {
      referer: 'https://www.google.com/',
      waitUntil: 'domcontentloaded',
      timeout: 0
    });

    logger.info('Waiting for Suno interface to load');
    // await page.locator('.react-aria-GridList').waitFor({ timeout: 60000 });
    await page.waitForResponse('**/api/project/**\\?**', { timeout: 60000 }); // wait for song list API call

    if (this.ghostCursorEnabled)
      this.cursor = await createCursor(page);
    
    logger.info('Triggering the CAPTCHA');
    try {
      await page.getByLabel('Close').click({ timeout: 2000 }); // close all popups
      // await this.click(page, { x: 318, y: 13 });
    } catch(e) {}

    const textarea = page.locator('.custom-textarea');
    await this.click(textarea);
    await textarea.pressSequentially('Lorem ipsum', { delay: 80 });

    const button = page.locator('button[aria-label="Create"]').locator('div.flex');
    this.click(button);

    const controller = new AbortController();
    new Promise<void>(async (resolve, reject) => {
      const frame = page.frameLocator('iframe[title*="hCaptcha"]');
      const challenge = frame.locator('.challenge-container');
      try {
        let wait = true;
        while (true) {
          if (wait)
            await waitForRequests(page, controller.signal);
          const drag = (await challenge.locator('.prompt-text').first().innerText()).toLowerCase().includes('drag');
          let captcha: any;
          for (let j = 0; j < 3; j++) { // try several times because sometimes 2Captcha could return an error
            try {
              logger.info('Sending the CAPTCHA to 2Captcha');
              const payload: paramsCoordinates = {
                body: (await challenge.screenshot({ timeout: 5000 })).toString('base64'),
                lang: process.env.BROWSER_LOCALE
              };
              if (drag) {
                // Say to the worker that he needs to click
                payload.textinstructions = 'CLICK on the shapes at their edge or center as shown above—please be precise!';
                payload.imginstructions = (await fs.readFile(path.join(process.cwd(), 'public', 'drag-instructions.jpg'))).toString('base64');
              }
              captcha = await this.solver.coordinates(payload);
              break;
            } catch(err: any) {
              logger.info(err.message);
              if (j != 2)
                logger.info('Retrying...');
              else
                throw err;
            }
          } 
          if (drag) {
            const challengeBox = await challenge.boundingBox();
            if (challengeBox == null)
              throw new Error('.challenge-container boundingBox is null!');
            if (captcha.data.length % 2) {
              logger.info('Solution does not have even amount of points required for dragging. Requesting new solution...');
              this.solver.badReport(captcha.id);
              wait = false;
              continue;
            }
            for (let i = 0; i < captcha.data.length; i += 2) {
              const data1 = captcha.data[i];
              const data2 = captcha.data[i+1];
              logger.info(JSON.stringify(data1) + JSON.stringify(data2));
              await page.mouse.move(challengeBox.x + +data1.x, challengeBox.y + +data1.y);
              await page.mouse.down();
              await sleep(1.1); // wait for the piece to be 'unlocked'
              await page.mouse.move(challengeBox.x + +data2.x, challengeBox.y + +data2.y, { steps: 30 });
              await page.mouse.up();
            }
            wait = true;
          } else {
            for (const data of captcha.data) {
              logger.info(data);
              await this.click(challenge, { x: +data.x, y: +data.y });
            };
          }
          this.click(frame.locator('.button-submit')).catch(e => {
            if (e.message.includes('viewport')) // when hCaptcha window has been closed due to inactivity,
              this.click(button); // click the Create button again to trigger the CAPTCHA
            else
              throw e;
          });
        }
      } catch(e: any) {
        if (e.message.includes('been closed') // catch error when closing the browser
          || e.message == 'AbortError') // catch error when waitForRequests is aborted
          resolve();
        else
          reject(e);
      }
    }).catch(e => {
      browser.browser()?.close();
      throw e;
    });
    return (new Promise((resolve, reject) => {
      page.route('**/api/generate/v2/**', async (route: any) => {
        try {
          logger.info('hCaptcha token received. Closing browser');
          route.abort();
          browser.browser()?.close();
          controller.abort();
          const request = route.request();
          this.currentToken = request.headers().authorization.split('Bearer ').pop();
          resolve(request.postDataJSON().token);
        } catch(err) {
          reject(err);
        }
      });
    }));
  }

  /**
   * Imitates Cloudflare Turnstile loading error. Unused right now, left for future
   */
  private async getTurnstile() {
    return this.client.post(
      `https://clerk.suno.com/v1/client?__clerk_api_version=2021-02-05&_clerk_js_version=${SunoApi.CLERK_VERSION}&_method=PATCH`,
      { captcha_error: '300030,300030,300030' },
      { headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  }

  /**
   * Generate a song based on the prompt.
   * @param prompt The text prompt to generate audio from.
   * @param make_instrumental Indicates if the generated audio should be instrumental.
   * @param wait_audio Indicates if the method should wait for the audio file to be fully generated before returning.
   * @returns
   */
  public async generate(
    prompt: string,
    make_instrumental: boolean = false,
    model?: string,
    wait_audio: boolean = false,
    cover_clip_id?:string,
  ): Promise<AudioInfo[]> {
    logger.info('Generate called with prompt: ' + prompt);
    await this.keepAlive(false);
    let task = '';
    if (cover_clip_id) task = 'cover';
    const startTime = Date.now();
    const audios = await this.generateSongs(
      prompt,
      false,
      undefined,
      undefined,
      make_instrumental,
      model,
      wait_audio,
      '',
      task,
      '',
      0,
      cover_clip_id,
      '',
      '',
    );
    const costTime = Date.now() - startTime;
    logger.info('Generate Response:\n' + JSON.stringify(audios, null, 2));
    logger.info('Cost time: ' + costTime);
    return audios;
  }

  /**
   * Calls the concatenate endpoint for a clip to generate the whole song.
   * @param clip_id The ID of the audio clip to concatenate.
   * @returns A promise that resolves to an AudioInfo object representing the concatenated audio.
   * @throws Error if the response status is not 200.
   */
  public async concatenate(clip_id: string): Promise<AudioInfo> {
    await this.keepAlive(false);
    const payload: any = { clip_id: clip_id };

    const response = await this.client.post(
      `${SunoApi.BASE_URL}/api/generate/concat/v2/`,
      payload,
      {
        timeout: 10000 // 10 seconds timeout
      }
    );
    if (response.status !== 200) {
      throw new Error('Error response:' + response.statusText);
    }
    return response.data;
  }

  /**
   * Generates custom audio based on provided parameters.
   *
   * @param prompt The text prompt to generate audio from.
   * @param tags Tags to categorize the generated audio.
   * @param title The title for the generated audio.
   * @param make_instrumental Indicates if the generated audio should be instrumental.
   * @param wait_audio Indicates if the method should wait for the audio file to be fully generated before returning.
   * @param negative_tags Negative tags that should not be included in the generated audio.
   * @returns A promise that resolves to an array of AudioInfo objects representing the generated audios.
   */
  public async custom_generate(
    prompt: string, // 自定义模式下只有歌词，没有描述
    tags: string, // 音乐风格标签
    title: string, // 音乐标题
    make_instrumental: boolean = false, // 是否为纯音乐
    model?: string, // 模型
    wait_audio: boolean = false, 
    negative_tags?: string, // 负面标签
    cover_clip_id?: string, // 参照的音频ID
    vocal_gender?: string // 人声性别
  ): Promise<AudioInfo[]> {
    let task = '';
    if (cover_clip_id) task = "cover";
    const startTime = Date.now();
    const audios = await this.generateSongs(
      "",
      true,
      tags,
      title,
      make_instrumental,
      model,
      wait_audio,
      negative_tags,
      task, 
      '',
      0,
      cover_clip_id,
      prompt,
      vocal_gender
    );
    const costTime = Date.now() - startTime;
    logger.info(
      'Custom Generate Response:\n' + JSON.stringify(audios, null, 2)
    );
    logger.info('Cost time: ' + costTime);
    return audios;
  }

  /**
   * Generates songs based on the provided parameters.
   *
   * @param prompt The text prompt to generate songs from.
   * @param isCustom Indicates if the generation should consider custom parameters like tags and title.
   * @param tags Optional tags to categorize the song, used only if isCustom is true.
   * @param title Optional title for the song, used only if isCustom is true.
   * @param make_instrumental Indicates if the generated song should be instrumental.
   * @param wait_audio Indicates if the method should wait for the audio file to be fully generated before returning.
   * @param negative_tags Negative tags that should not be included in the generated audio.
   * @param task Optional indication of what to do. Enter 'extend' if extending an audio, otherwise specify null.
   * @param continue_clip_id 
   * @returns A promise that resolves to an array of AudioInfo objects representing the generated songs.
   */

  /**
   * Generates songs based on the provided parameters.
   * [Updated for v5 / v2-web endpoint].
   */
  private async generateSongs(
    prompt: string,
    isCustom: boolean,
    tags?: string,
    title?: string,
    make_instrumental?: boolean,
    model?: string,
    wait_audio: boolean = false,
    negative_tags?: string,
    task?: string,
    continue_clip_id?: string,
    continue_at?: number,
    cover_clip_id?: string, // 自定义音乐
    lyrics_prompt?: string, // 歌词
    vocal_gender?: string // 人声性别
  ): Promise<AudioInfo[]> {
    logger.info('generateSongs called with prompt: ' + prompt);

    await this.keepAlive();

    // [v5 Support] model name mapping (chirp-v5-0 -> chirp-crow)
    let mv = model || DEFAULT_MODEL;
    if (mv === 'chirp-v5-0' || mv === 'v5') {
      mv = 'chirp-crow';
    }

    // [v5 Security] create session token, transaction ID
    const sessionToken = await this.getSessionToken();
    const transactionId = randomUUID();

    // [v5 Payload] modify construction for v2-web endpoint
    const payload: any = {
      token: await this.getCaptcha(),
      generation_type: 'TEXT',
      title: title || '',
      tags: tags || '',
      negative_tags: negative_tags || '',
      mv: mv,
      prompt: lyrics_prompt, // 歌词
      gpt_description_prompt: prompt,
      make_instrumental: make_instrumental,
      user_uploaded_images_b64: null,
      metadata: {
        web_client_pathname: '/create',
        is_max_mode: false,
        create_mode: isCustom ? 'custom' : 'simple',
        is_mumble: false,
        create_session_token: sessionToken, // required
        disable_volume_normalization: false,
        can_control_sliders: ["weirdness_constraint", "style_weight"],
        // exclude user_tier cause it could be optional (if error, need to fix it)
        lyrics_model:'default',
        vocal_gender:vocal_gender
      },
      override_fields: [],
      transaction_uuid: transactionId // 필수
    };

    // extra parameter for extension task
    if (task === 'extend') {
      payload.continue_clip_id = continue_clip_id;
      payload.continue_at = continue_at;
      payload.task = task;
    } else if (task === 'cover') {
      payload.cover_clip_id = cover_clip_id;
      payload.task = task;
    }

    logger.info(
      'generateSongs payload (v2-web):\n' +
        JSON.stringify(
          {
            model: mv,
            prompt: prompt,
            tags: tags,
            title: title,
            payload: payload
          },
          null,
          2
        )
    );

    // [v5 Endpoint] send to /api/generate/v2-web/
    const response = await this.client.post(
      `${SunoApi.BASE_URL}/api/generate/v2-web/`,
      payload,
      {
        timeout: 10000 
      }
    );

    if (response.status !== 200) {
      throw new Error('Error response:' + response.statusText);
    }

    const songIds = response.data.clips.map((audio: any) => audio.id);

    // Wait logic (same as before)
    if (wait_audio) {
      const startTime = Date.now();
      let lastResponse: AudioInfo[] = [];
      await sleep(5, 5);
      while (Date.now() - startTime < 100000) {
        const response = await this.get(songIds);
        const allCompleted = response.every(
          (audio) => audio.status === 'streaming' || audio.status === 'complete'
        );
        const allError = response.every((audio) => audio.status === 'error');
        if (allCompleted || allError) {
          return response;
        }
        lastResponse = response;
        await sleep(3, 6);
        await this.keepAlive(true);
      }
      return lastResponse;
    } else {
      return response.data.clips.map((audio: any) => ({
        id: audio.id,
        title: audio.title,
        image_url: audio.image_url,
        lyric: audio.metadata.prompt,
        audio_url: audio.audio_url,
        video_url: audio.video_url,
        created_at: audio.created_at,
        model_name: audio.model_name,
        status: audio.status,
        gpt_description_prompt: audio.metadata.gpt_description_prompt,
        prompt: audio.metadata.prompt,
        type: audio.metadata.type,
        tags: audio.metadata.tags,
        negative_tags: audio.metadata.negative_tags,
        duration: audio.metadata.duration
      }));
    }
  }

  /**
   * Generates lyrics based on a given prompt.
   * @param prompt The prompt for generating lyrics.
   * @returns The generated lyrics text.
   */
  public async generateLyrics(prompt: string): Promise<string> {
    await this.keepAlive(false);
    // Initiate lyrics generation
    const generateResponse = await this.client.post(
      `${SunoApi.BASE_URL}/api/generate/lyrics/`,
      { prompt }
    );
    const generateId = generateResponse.data.id;

    // Poll for lyrics completion
    let lyricsResponse = await this.client.get(
      `${SunoApi.BASE_URL}/api/generate/lyrics/${generateId}`
    );
    while (lyricsResponse?.data?.status !== 'complete') {
      await sleep(2); // Wait for 2 seconds before polling again
      lyricsResponse = await this.client.get(
        `${SunoApi.BASE_URL}/api/generate/lyrics/${generateId}`
      );
    }

    // Return the generated lyrics text
    return lyricsResponse.data;
  }

  /**
   * Extends an existing audio clip by generating additional content based on the provided prompt.
   *
   * @param audioId The ID of the audio clip to extend.
   * @param prompt The prompt for generating additional content.
   * @param continueAt Extend a new clip from a song at mm:ss(e.g. 00:30). Default extends from the end of the song.
   * @param tags Style of Music.
   * @param title Title of the song.
   * @returns A promise that resolves to an AudioInfo object representing the extended audio clip.
   */
  public async extendAudio(
    audioId: string,
    prompt: string = '',
    continueAt: number,
    tags: string = '',
    negative_tags: string = '',
    title: string = '',
    model?: string,
    wait_audio?: boolean
  ): Promise<AudioInfo[]> {
    return this.generateSongs(prompt, true, tags, title, false, model, wait_audio, negative_tags, 'extend', audioId, continueAt);
  }

  /**
   * Generate stems for a song.
   * @param song_id The ID of the song to generate stems for.
   * @returns A promise that resolves to an AudioInfo object representing the generated stems.
   */
  public async generateStems(song_id: string): Promise<AudioInfo[]> {
    await this.keepAlive(false);
    const response = await this.client.post(
      `${SunoApi.BASE_URL}/api/edit/stems/${song_id}`, {}
    );

    console.log('generateStems response:\n', response?.data);
    return response.data.clips.map((clip: any) => ({
      id: clip.id,
      status: clip.status,
      created_at: clip.created_at,
      title: clip.title,
      stem_from_id: clip.metadata.stem_from_id,
      duration: clip.metadata.duration
    }));
  }


  /**
   * Get the lyric alignment for a song.
   * @param song_id The ID of the song to get the lyric alignment for.
   * @returns A promise that resolves to an object containing the lyric alignment.
   */
  public async getLyricAlignment(song_id: string): Promise<object> {
    await this.keepAlive(false);
    const response = await this.client.get(`${SunoApi.BASE_URL}/api/gen/${song_id}/aligned_lyrics/v2/`);

    console.log(`getLyricAlignment ~ response:`, response.data);
    return response.data?.aligned_words.map((transcribedWord: any) => ({
      word: transcribedWord.word,
      start_s: transcribedWord.start_s,
      end_s: transcribedWord.end_s,
      success: transcribedWord.success,
      p_align: transcribedWord.p_align
    }));
  }

  /**
   * Processes the lyrics (prompt) from the audio metadata into a more readable format.
   * @param prompt The original lyrics text.
   * @returns The processed lyrics text.
   */
  private parseLyrics(prompt: string): string {
    // Assuming the original lyrics are separated by a specific delimiter (e.g., newline), we can convert it into a more readable format.
    // The implementation here can be adjusted according to the actual lyrics format.
    // For example, if the lyrics exist as continuous text, it might be necessary to split them based on specific markers (such as periods, commas, etc.).
    // The following implementation assumes that the lyrics are already separated by newlines.

    // Split the lyrics using newline and ensure to remove empty lines.
    const lines = prompt.split('\n').filter((line) => line.trim() !== '');

    // Reassemble the processed lyrics lines into a single string, separated by newlines between each line.
    // Additional formatting logic can be added here, such as adding specific markers or handling special lines.
    return lines.join('\n');
  }

  /**
   * Retrieves audio information for the given song IDs.
   * @param songIds An optional array of song IDs to retrieve information for.
   * @param page An optional page number to retrieve audio information from.
   * @returns A promise that resolves to an array of AudioInfo objects.
   */
  public async get(
    songIds?: string[],
    page?: string | null
  ): Promise<AudioInfo[]> {
    await this.keepAlive(false);
    let url = new URL(`${SunoApi.BASE_URL}/api/feed/v2`);
    if (songIds) {
      url.searchParams.append('ids', songIds.join(','));
    }
    if (page) {
      url.searchParams.append('page', page);
    }
    logger.info('Get audio status: ' + url.href);
    const response = await this.client.get(url.href, {
      // 10 seconds timeout
      timeout: 10000
    });

    const audios = response.data.clips;

    return audios.map((audio: any) => ({
      id: audio.id,
      title: audio.title,
      image_url: audio.image_url,
      lyric: audio.metadata.prompt
        ? this.parseLyrics(audio.metadata.prompt)
        : '',
      audio_url: audio.audio_url,
      video_url: audio.video_url,
      created_at: audio.created_at,
      model_name: audio.model_name,
      status: audio.status,
      gpt_description_prompt: audio.metadata.gpt_description_prompt,
      prompt: audio.metadata.prompt,
      type: audio.metadata.type,
      tags: audio.metadata.tags,
      duration: audio.metadata.duration,
      error_message: audio.metadata.error_message
    }));
  }

  /**
   * Retrieves information for a specific audio clip.
   * @param clipId The ID of the audio clip to retrieve information for.
   * @returns A promise that resolves to an object containing the audio clip information.
   */
  public async getClip(clipId: string): Promise<object> {
    await this.keepAlive(false);
    const response = await this.client.get(
      `${SunoApi.BASE_URL}/api/clip/${clipId}`
    );
    return response.data;
  }

  public async get_credits(): Promise<object> {
    await this.keepAlive(false);
    const response = await this.client.get(
      `${SunoApi.BASE_URL}/api/billing/info/`
    );
    return {
      credits_left: response.data.total_credits_left,
      period: response.data.period,
      monthly_limit: response.data.monthly_limit,
      monthly_usage: response.data.monthly_usage
    };
  }

  public async getPersonaPaginated(personaId: string, page: number = 1): Promise<PersonaResponse> {
    await this.keepAlive(false);
    
    const url = `${SunoApi.BASE_URL}/api/persona/get-persona-paginated/${personaId}/?page=${page}`;
    
    logger.info(`Fetching persona data: ${url}`);
    
    const response = await this.client.get(url, {
      timeout: 10000 // 10 seconds timeout
    });

    if (response.status !== 200) {
      throw new Error('Error response: ' + response.statusText);
    }

    return response.data;
  }

  // --------------------------- upload mp3 file ---------------------------
  // 检查上传结果
  private async getUploadFileResult(fileKey: string): Promise<any> {
    await this.keepAlive(false);
    const response = await this.client.get(
      `${SunoApi.BASE_URL}/api/uploads/audio/${fileKey}/`
    )
    if (response.status == 200 && response.data.status == 'complete') {
      return {status: 'complete', audioUrl: response.data.audio_url};
    }
    return {status: 'pending'};
  }

  // 上传文件到Aws
  // form 表单数据上传，接收二进制文件
  public async uploadFileToAws(base64File: string, fileName: string, fileType: string): Promise<any> {
    const awsInfoResponse = await this.client.post(
      `https://studio-api.prod.suno.com/api/uploads/audio/`,
      {
        extension: fileType
      }
    );
    if (awsInfoResponse.status != 200) {
      throw new Error('Error response status:' + awsInfoResponse.status);
    }
    const uploadInfo = awsInfoResponse.data;

    // 上传到 aws
    const field = uploadInfo.fields;
    const form = new FormData();
    form.append('Content-Type', field['Content-Type']);
    form.append('key', field.key);
    form.append('AWSAccessKeyId', field.AWSAccessKeyId);
    form.append('policy', field.policy);
    form.append('signature', field.signature);
      
    const fileTemp = base64ToFile(base64File, fileName, field['Content-Type']);
    form.append('file', fileTemp);
    const awsResponse = await this.client.post(
      uploadInfo.url,
      form
    );
    if (awsResponse.status != 204) {
      throw new Error('Error response status:' + awsResponse.status);
    }
    
    // 请求到 suno
    let fileKey = field.key.split('/')[1]
    fileKey = fileKey.split('.')[0]; // 去掉后缀
    const url = `${SunoApi.BASE_URL}/api/uploads/audio/${fileKey}/upload-finish/`;
    const response = await this.client.post(
      url,
      {upload_type:"file_upload",upload_filename:fileName}
    );
    if (response.status != 200) {
      throw new Error('Error response status:' + response.status);
    }

    // 轮询结果
    let uploadResult = await this.getUploadFileResult(fileKey);
    const startTime = Date.now();
    while (uploadResult.status == 'pending' && (Date.now() - startTime) < 60000) { // 最多等1分钟
      await sleep(3, 6);
      uploadResult = await this.getUploadFileResult(fileKey);
    }
    if (uploadResult.status != 'complete') {
      throw new Error('Upload file processing timeout or failed');
    }

    // initialize 生成clip id
    const initResponse = await this.client.post(
      `${SunoApi.BASE_URL}/api/uploads/audio/${fileKey}/initialize-clip/`,
      {}
    );
    if (initResponse.status != 200) {
      throw new Error('Error response status:' + initResponse.status);
    }

    // 返回key
    return { 
      clip_id: initResponse.data.clip_id,
      file_name: fileName,
      file_type: fileType
    }; 
  }

  // -------------------- 上传文件结束--------------------
}

export const sunoApi = async (cookie?: string) => {
  const resolvedCookie = cookie && cookie.includes('__client') ? cookie : process.env.SUNO_COOKIE; // Check for bad `Cookie` header (It's too expensive to actually parse the cookies *here*)
  if (!resolvedCookie) {
    logger.info('No cookie provided! Aborting...\nPlease provide a cookie either in the .env file or in the Cookie header of your request.')
    throw new Error('Please provide a cookie either in the .env file or in the Cookie header of your request.');
  }

  // Check if the instance for this cookie already exists in the cache
  const cachedInstance = cache.get(resolvedCookie);
  if (cachedInstance)
    return cachedInstance;

  // If not, create a new instance and initialize it
  const instance = await new SunoApi(resolvedCookie).init();
  // Cache the initialized instance
  cache.set(resolvedCookie, instance);

  return instance;
};