import { useCallback, useMemo, useRef, useState, type DragEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { DayPicker } from 'react-day-picker';
import { es } from 'react-day-picker/locale';
import { FileSpreadsheet, Upload, Loader2, CloudUpload, ArrowRight, Hash } from 'lucide-react';
import { toast } from 'sonner';
import { can } from '@soc/shared';
import { useUploadDays, useUploadFile, useUploadsByDay } from '../api/hooks';
import { useSession } from '../lib/session';
import { Empty, Modal, PageHeader, Spinner } from '../components/ui';
import { dateToYmd, fmtBytes, fmtTime, todayLocal, ymdToDate } from '../lib/format';

function UploadDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [drag, setDrag] = useState(false);
  const upload = useUploadFile();
  const navigate = useNavigate();

  const pick = (f: File | undefined) => {
    if (!f) return;
    if (!/\.xlsx$/i.test(f.name)) {
      toast.error('Solo se permiten archivos Excel .xlsx');
      return;
    }
    setFile(f);
  };
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDrag(false);
    pick(e.dataTransfer.files[0]);
  };
  const submit = () =>
    file &&
    upload.mutate(file, {
      onSuccess: (r) => {
        toast.success(`Archivo cargado: ${r.upload.rowCount} eventos importados`);
        if (r.missingColumns.length) toast.warning(`Columnas no encontradas: ${r.missingColumns.join(', ')}`);
        onClose();
        setFile(null);
        navigate(`/uploads/${r.upload.id}`);
      },
    });

  return (
    <Modal open={open} onClose={onClose} title="Upload Log File">
      <div
        onDragOver={(e) => (e.preventDefault(), setDrag(true))}
        onDragLeave={() => setDrag(false)}
        onDrop={onDrop}
        onClick={() => input.current?.click()}
        className={`flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed px-6 py-10 text-center transition ${
          drag ? 'border-accent bg-accent/5' : 'border-ink-600 hover:border-slate-500'
        }`}
      >
        <CloudUpload className="h-10 w-10 text-accent" />
        <div>
          <p className="font-medium text-slate-200">Arrastra el export del SIEM o haz clic para seleccionarlo</p>
          <p className="mt-1 text-xs text-slate-500">Solo archivos Excel .xlsx · Columnas: Log_ID, Timestamp, Hostname, Event_ID, User, Source_IP...</p>
        </div>
        <input
          ref={input}
          type="file"
          className="hidden"
          accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
          onChange={(e) => pick(e.target.files?.[0])}
        />
      </div>
      {file && (
        <div className="mt-4 flex items-center gap-3 rounded-lg border border-ink-700 bg-ink-850 p-3">
          <FileSpreadsheet className="h-6 w-6 text-emerald-400" />
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm text-slate-200">{file.name}</p>
            <p className="text-xs text-slate-500">{fmtBytes(file.size)}</p>
          </div>
        </div>
      )}
      {upload.isError && <p className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{upload.error.message}</p>}
      <div className="mt-5 flex justify-end gap-2">
        <button className="btn-ghost" onClick={onClose}>
          Cancelar
        </button>
        <button className="btn-primary" disabled={!file || upload.isPending} onClick={submit}>
          {upload.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />} Cargar e importar
        </button>
      </div>
    </Modal>
  );
}

export function UploadsPage() {
  const { me } = useSession();
  const [params, setParams] = useSearchParams();
  const date = params.get('date') ?? todayLocal();
  const [month, setMonth] = useState(() => ymdToDate(date));
  const monthKey = `${month.getFullYear()}-${String(month.getMonth() + 1).padStart(2, '0')}`;
  const list = useUploadsByDay(date);
  const days = useUploadDays(monthKey);
  const dialogOpen = params.get('upload') === '1';
  const setDialog = useCallback(
    (open: boolean) =>
      setParams(
        (p) => {
          if (open) p.set('upload', '1');
          else p.delete('upload');
          return p;
        },
        { replace: true },
      ),
    [setParams],
  );
  const highlighted = useMemo(() => (days.data ?? []).map((d) => ymdToDate(d.day)), [days.data]);

  return (
    <>
      <PageHeader
        title="Logs y análisis"
        subtitle="Selecciona una fecha para ver los archivos cargados ese día. Los días con cargas aparecen marcados."
        actions={
          can(me.user.role, 'uploads:create') && (
            <button className="btn-primary" onClick={() => setDialog(true)}>
              <Upload className="h-4 w-4" /> Upload Log File
            </button>
          )
        }
      />
      <div className="grid gap-6 lg:grid-cols-[auto_1fr]">
        <div className="card self-start p-4">
          <DayPicker
            mode="single"
            locale={es}
            selected={ymdToDate(date)}
            onSelect={(d) => d && setParams({ date: dateToYmd(d) })}
            month={month}
            onMonthChange={setMonth}
            modifiers={{ hasUploads: highlighted }}
            modifiersClassNames={{ hasUploads: 'rdp-has-uploads' }}
            showOutsideDays
          />
          <button className="btn-ghost mt-2 w-full py-1.5 text-xs" onClick={() => (setParams({ date: todayLocal() }), setMonth(ymdToDate(todayLocal())))}>
            Ir a hoy
          </button>
        </div>

        <div className="card p-5">
          <h2 className="mb-4 font-semibold text-white">
            Archivos del {ymdToDate(date).toLocaleDateString('es-PA', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })}
          </h2>
          {list.isLoading ? (
            <Spinner />
          ) : list.data?.length ? (
            <div className="space-y-2">
              {list.data.map((u) => (
                <Link
                  key={u.id}
                  to={`/uploads/${u.id}`}
                  className="group flex items-center gap-4 rounded-lg border border-ink-700 bg-ink-850 p-4 transition hover:border-accent/50 hover:bg-ink-800"
                >
                  <FileSpreadsheet className="h-8 w-8 shrink-0 text-emerald-400" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium text-slate-100">{u.originalName}</p>
                    <p className="mt-0.5 text-xs text-slate-500">
                      {fmtTime(u.uploadedAt)} · {u.uploadedBy} · {u.rowCount} eventos · {fmtBytes(u.sizeBytes)} · guardado como <span className="font-mono">{u.storedName}</span>
                    </p>
                    <p className="mt-0.5 flex items-center gap-1 font-mono text-[10px] text-slate-600" title="SHA-256 del archivo (cadena de custodia)">
                      <Hash className="h-3 w-3" />
                      {u.sha256}
                    </p>
                  </div>
                  <span className={`rounded-md px-2 py-1 text-xs ${u.analysisCount ? 'bg-emerald-500/10 text-emerald-300' : 'bg-ink-700 text-slate-400'}`}>
                    {u.analysisCount ? `${u.analysisCount} análisis` : 'Sin analizar'}
                  </span>
                  <ArrowRight className="h-4 w-4 text-slate-600 group-hover:text-accent" />
                </Link>
              ))}
            </div>
          ) : (
            <Empty title="No Data Available for this Date">No hay archivos cargados en esta fecha. Usa “Upload Log File” para importar un export del SIEM.</Empty>
          )}
        </div>
      </div>
      <UploadDialog open={dialogOpen} onClose={() => setDialog(false)} />
    </>
  );
}
