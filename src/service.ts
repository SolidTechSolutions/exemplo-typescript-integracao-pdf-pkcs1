'use strict';
/**
 * [EN]    Two-step PAdES PDF signing — PKCS#1 (external private key / browser extension).
 * [PT-BR] Assinatura PAdES PDF em dois passos — PKCS#1 (chave privada externa / extensão do browser).
 */
import axios from 'axios';
import FormData from 'form-data';
import fs from 'fs';
import path from 'path';

interface PrepareParams {
  authorization: string; baseUrl: string; certificate: string;
  documents: Express.Multer.File[]; signatureImages?: Express.Multer.File[];
  profile?: string; hashAlgorithm?: string; policyVersion?: string;
  sigFieldMeasurementUnit?: string; signatureFieldConfig?: string;
  reason?: string; location?: string; contact?: string;
  signatureFieldName?: string; signatureTextConfig?: string;
  mdpPermissionLevel?: string; passwordsForDecryption?: string;
  documentInfoMetadata?: string; signatureQrCodeConfig?: string;
}

// [EN]    Sends a visual-signature config as INDEXED fields: key[0], key[1], ...
//         The SolidSign API expects signatureFieldConfig[0]={...} per document, NOT a single
//         signatureFieldConfig=[{...}] — otherwise the field is ignored and the stamp never appears.
// [PT-BR] Envia a config de assinatura visual como campos INDEXADOS: key[0], key[1], ...
//         A API espera signatureFieldConfig[0]={...} por documento, e NÃO um único
//         signatureFieldConfig=[{...}] — senão o campo é ignorado e o carimbo não aparece.
function appendIndexedJson(form: FormData, key: string, raw?: string): void {
  if (!raw) return;
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { form.append(`${key}[0]`, raw); return; }
  const items: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  items.forEach((it, i) => form.append(`${key}[${i}]`, typeof it === 'string' ? it : JSON.stringify(it)));
}

export class PdfPkcs1Service {
  private readonly baseUrl = (process.env.SOLIDSIGN_API_BASE_URL ?? '').replace(/\/$/, '');
  private readonly authorization = process.env.SOLIDSIGN_API_AUTHORIZATION ?? '';
  private readonly profile = process.env.SOLIDSIGN_SIG_PROFILE ?? 'ADRB';
  private readonly hashAlgorithm = process.env.SOLIDSIGN_SIG_HASH_ALGORITHM ?? 'SHA256';
  private readonly sigFieldMeasurementUnit = process.env.SOLIDSIGN_SIG_FIELD_MEASUREMENT_UNIT ?? 'PIXELS';
  private readonly signatureFieldConfig = process.env.SOLIDSIGN_SIG_FIELD_CONFIG ?? '';
  private readonly reason = process.env.SOLIDSIGN_SIG_REASON ?? '';
  private readonly location = process.env.SOLIDSIGN_SIG_LOCATION ?? '';
  private readonly contact = process.env.SOLIDSIGN_SIG_CONTACT ?? '';
  private readonly signerCertPem = process.env.SOLIDSIGN_CERT_PEM ?? '';
  private readonly signatureImagePaths = (process.env.SOLIDSIGN_SIG_IMAGE_PATHS ?? '')
    .split(',').map(p => p.trim()).filter(Boolean);

  async prepareSignature(documents: Express.Multer.File[]): Promise<unknown> {
    const form = new FormData();
    documents.forEach((d, i) => form.append(`document[${i}]`, d.buffer, { filename: d.originalname }));
    this.signatureImagePaths.forEach((img, i) => {
      if (fs.existsSync(img)) form.append(`signatureImage[${i}]`, fs.createReadStream(img), { filename: path.basename(img) });
    });
    form.append('profile', this.profile); form.append('hashAlgorithm', this.hashAlgorithm);
    form.append('sigFieldMeasurementUnit', this.sigFieldMeasurementUnit);
    appendIndexedJson(form, 'signatureFieldConfig', this.signatureFieldConfig);
    form.append('reason', this.reason); form.append('location', this.location);
    form.append('contact', this.contact); form.append('certificate', this.signerCertPem);
    try {
      const r = await axios.post(`${this.baseUrl}/solidsign/dsig/pdf/pkcs1/sign-preparation`, form,
        { headers: { Authorization: this.authorization, ...form.getHeaders() }, timeout: 120000 });
      console.info(`PDF PKCS1 preparation OK. finalNonce=${(r.data as Record<string,string>).finalNonce}`);
      return r.data;
    } catch (err) { this.logError('prepare', err); return null; }
  }

  async finalizeSignature(params: Record<string, string>): Promise<unknown> {
    const form = new FormData();
    Object.entries(params).forEach(([k, v]) => form.append(k, v));
    try {
      const r = await axios.post(`${this.baseUrl}/solidsign/dsig/pdf/pkcs1/sign-finalization`, form,
        { headers: { Authorization: this.authorization, ...form.getHeaders() }, timeout: 120000 });
      return r.data;
    } catch (err) { this.logError('finalize', err); return null; }
  }

  async prepareForm(p: PrepareParams): Promise<unknown> {
    const form = new FormData();
    p.documents.forEach((d, i) => form.append(`document[${i}]`, d.buffer, { filename: d.originalname }));
    (p.signatureImages ?? []).forEach((img, i) => form.append(`signatureImage[${i}]`, img.buffer, { filename: img.originalname }));
    form.append('certificate', p.certificate);
    if (p.profile)                  form.append('profile', p.profile);
    if (p.hashAlgorithm)            form.append('hashAlgorithm', p.hashAlgorithm);
    if (p.policyVersion)            form.append('policyVersion', p.policyVersion);
    if (p.sigFieldMeasurementUnit)  form.append('sigFieldMeasurementUnit', p.sigFieldMeasurementUnit);
    if (p.signatureFieldConfig)     appendIndexedJson(form, 'signatureFieldConfig', p.signatureFieldConfig);
    if (p.reason)                   form.append('reason', p.reason);
    if (p.location)                 form.append('location', p.location);
    if (p.contact)                  form.append('contact', p.contact);
    if (p.signatureFieldName)       form.append('signatureFieldName', p.signatureFieldName);
    if (p.signatureTextConfig)      appendIndexedJson(form, 'signatureTextConfig', p.signatureTextConfig);
    if (p.mdpPermissionLevel)       form.append('mdpPermissionLevel', p.mdpPermissionLevel);
    if (p.passwordsForDecryption)   form.append('passwordsForDecryption', p.passwordsForDecryption);
    if (p.documentInfoMetadata)     form.append('documentInfoMetadata', p.documentInfoMetadata);
    if (p.signatureQrCodeConfig)    appendIndexedJson(form, 'signatureQrCodeConfig', p.signatureQrCodeConfig);
    try {
      const r = await axios.post(`${p.baseUrl.replace(/\/$/, '')}/solidsign/dsig/pdf/pkcs1/sign-preparation`, form,
        { headers: { Authorization: p.authorization, ...form.getHeaders() }, timeout: 120000 });
      return r.data;
    } catch (err) { this.logError('prepare form', err); return null; }
  }

  async finalizeForm(authorization: string, baseUrl: string, params: Record<string, string>): Promise<unknown> {
    const form = new FormData();
    Object.entries(params).forEach(([k, v]) => form.append(k, v));
    try {
      const r = await axios.post(`${baseUrl.replace(/\/$/, '')}/solidsign/dsig/pdf/pkcs1/sign-finalization`, form,
        { headers: { Authorization: authorization, ...form.getHeaders() }, timeout: 120000 });
      return r.data;
    } catch (err) { this.logError('finalize form', err); return null; }
  }

  private logError(ctx: string, err: unknown): void {
    if (axios.isAxiosError(err))
      console.error(`SolidSign error ${err.response?.status} [${ctx}]: ${JSON.stringify(err.response?.data)}`);
    else console.error(`Unexpected error [${ctx}]: ${(err as Error).message}`);
  }
}
