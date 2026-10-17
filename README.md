# bot-seguranca-grupo

Bot moderador automático para grupos WhatsApp (prototype com whatsapp-web.js + VirusTotal).

Principais recursos:
- Apaga links não autorizados
- Apaga mensagens com ofensas/profanidade
- Detecta e remove flooders
- Boas-vindas automáticas
- Integração opcional com VirusTotal para checagem de URLs e arquivos

Atenção: usa whatsapp-web.js (emulação do WhatsApp Web). Risco de suspensão/ban do número existe. Teste em um grupo de teste antes de usar no principal.

---

## Preparação (local)

1. Crie pasta, cole os arquivos e entre nela:
   mkdir bot-seguranca-grupo && cd bot-seguranca-grupo

2. Copie os arquivos fornecidos para esta pasta.

3. Copie exemplos:
   cp config.example.json config.json
   cp .env.example .env

4. Edite `config.json` e `.env` com seus valores (admins, whitelist, VIRUSTOTAL_API_KEY etc.)

5. Instale dependências:
   npm ci

6. Inicie localmente:
   npm start
   - No primeiro start será exibido o QR no terminal. Escaneie com o WhatsApp do número que será o bot.

7. Para rodar 24/7 use PM2 ou Docker (veja instruções separadas no README completo).

---

Veja README.md completo no repositório para instruções de deploy em VPS, Docker e PM2.
