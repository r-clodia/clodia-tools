# Topic con remote Google Drive — modello

> Design note. Fonte di verità del comportamento: `service.py` + `test_drive_live.py`.

## Principio

Quando un topic è collegato a una cartella Google Drive, **Drive è la source of
truth**. Non esiste alcuna "migrazione" o upload dei file locali verso Drive:
Drive è già la verità e si **naviga direttamente il remoto**.

- I file locali del topic **spariscono dalla vista**: non vengono mostrati, non
  sincronizzati, non caricati. `list`/`read`/`write`/`delete` proxano
  direttamente al backend Drive (`DriveStorage`).
- **Nessun marker, nessun upload, nessuna verifica-e-clear.** Collegare Drive è
  un'operazione di *metadata* (`meta.remote = {type: drive, config}`), non di
  trasferimento dati.

## Collegare Drive (`remote_enable` / `new(want_drive)`)

Collegare Drive **presuppone che il contenuto sia già nella cartella Drive**
(appena provisionata e vuota, oppure pre-popolata). Due guardie:

1. **Anti-nascondimento**: se il topic ha file **solo in locale**, collegarli a
   Drive li renderebbe invisibili (non vengono caricati) → `remote_enable`
   **rifiuta**. Va prima popolata la cartella Drive, oppure il topic resta
   `local-fs`.
2. **Cap SEAL (anti-declassamento, Prima Legge/GDPR)**: un topic di tier
   superiore a `_DRIVE_SEAL_CAP` (SEAL-2) non può usare Drive come storage live.

## Scollegare Drive (`remote_disable`)

È l'unico trasferimento previsto, ed è l'inverso: **materializza Drive → locale**
(`_drive_pull_tree`, ripartibile, senza clear preventivo) così il topic torna
`local-fs` con i suoi file. Se il pull fallisce a metà, Drive resta la fonte →
nessuna perdita.

## Editing di un agente (scratch)

Un agente che deve **lavorare** su un file non passa mai per un filesystem
intermedio del topic: lo **scarica nel proprio scratch** (`read_file` →
download da Drive), lo modifica nel suo workspace, e lo **ricarica** (`put_file`
/ `write_file` → upload diretto a Drive). Il topic-fs non ospita mai copie di
lavoro.

## Legacy `storage: google-drive`

I topic col vecchio `storage: google-drive` avevano i file **già** su Drive: la
conversione a `remote: drive` (`_migrate_legacy_drive`) è puro metadata, **nessun
upload/clear**.

## Cosa è stato rimosso (e perché)

Il modello precedente trattava Drive come destinazione di una *migrazione*:
`_ensure_drive_live` caricava l'albero locale su Drive (`_upload_local_tree`), lo
verificava, cancellava il locale (`_clear_local_files`) e segnava un marker
`.drive-live-v1` — il tutto **sincrono sul percorso di lettura** e **ritentato ad
ogni accesso** in caso di errore. Con una cartella Drive non scrivibile (403)
questo saturava il gateway (loop di upload falliti). Errore concettuale alla
radice: una **lettura non deve innescare una scrittura**, e collegare Drive non è
un upload. Tutto l'apparato è stato eliminato.
