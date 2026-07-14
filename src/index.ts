'use strict';
/**
 * [EN]    PAdES PDF two-step signing — PKCS#1 browser extension.  Port 8089.
 *         POST /api/pdf/pkcs1/prepare  → returns hashes + finalNonce
 *         POST /api/pdf/pkcs1/finalize → receives signed hashes, returns result
 * [PT-BR] Assinatura PAdES PDF em dois passos — extensão do browser PKCS#1.  Porta 8089.
 */
import 'dotenv/config';
import express, { Request, Response } from 'express';
import multer from 'multer';
import { PdfPkcs1Service } from './service';

const app = express();
app.use(express.urlencoded({ extended: true }));
const upload = multer({ storage: multer.memoryStorage() });
const service = new PdfPkcs1Service();

app.post('/api/pdf/pkcs1/prepare', upload.fields([{ name: 'document' }, { name: 'signatureImage' }]),
  async (req: Request, res: Response) => {
    const files = req.files as Record<string, Express.Multer.File[]>;
    const result = await service.prepareSignature(files['document'] ?? []);
    return result ? res.json(result) : res.status(500).json({ error: 'Preparation failed.' });
  });

app.post('/api/pdf/pkcs1/finalize', async (req: Request, res: Response) => {
  const result = await service.finalizeSignature(req.body as Record<string, string>);
  return result ? res.json(result) : res.status(500).json({ error: 'Finalization failed.' });
});

app.post('/api/pdf/pkcs1/prepare/form', upload.fields([{ name: 'document' }, { name: 'signatureImage' }]),
  async (req: Request, res: Response) => {
    const files = req.files as Record<string, Express.Multer.File[]>;
    const b = req.body as Record<string, string>;
    const result = await service.prepareForm({
      authorization: b.authorization, baseUrl: b.baseUrl, certificate: b.certificate,
      documents: files['document'] ?? [], signatureImages: files['signatureImage'] ?? [],
      profile: b.profile, hashAlgorithm: b.hashAlgorithm, policyVersion: b.policyVersion,
      sigFieldMeasurementUnit: b.sigFieldMeasurementUnit, signatureFieldConfig: b.signatureFieldConfig,
      reason: b.reason, location: b.location, contact: b.contact,
      signatureFieldName: b.signatureFieldName, signatureTextConfig: b.signatureTextConfig,
      mdpPermissionLevel: b.mdpPermissionLevel, passwordsForDecryption: b.passwordsForDecryption,
      documentInfoMetadata: b.documentInfoMetadata, signatureQrCodeConfig: b.signatureQrCodeConfig,
    });
    return result ? res.json(result) : res.status(500).json({ error: 'Preparation failed.' });
  });

app.post('/api/pdf/pkcs1/finalize/form', async (req: Request, res: Response) => {
  const { authorization, baseUrl, ...rest } = req.body as Record<string, string>;
  const result = await service.finalizeForm(authorization, baseUrl, rest);
  return result ? res.json(result) : res.status(500).json({ error: 'Finalization failed.' });
});

const PORT = Number(process.env.PORT ?? 8089);
app.listen(PORT, () => console.info(`SolidSign PDF PKCS1 (TS) running on port ${PORT}`));
