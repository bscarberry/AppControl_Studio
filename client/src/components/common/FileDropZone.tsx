import { useRef, useState } from "react";
import { Upload, File } from "lucide-react";
import clsx from "clsx";

interface FileDropZoneProps {
  accept?: string;
  label: string;
  description?: string;
  onFile: (content: string, fileName: string) => void;
  className?: string;
}

export function FileDropZone({ accept, label, description, onFile, className }: FileDropZoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [loadedFile, setLoadedFile] = useState<string | null>(null);

  const handleFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setLoadedFile(file.name);
      onFile(content, file.name);
    };
    reader.readAsText(file, "utf-8");
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
  };

  return (
    <div
      className={clsx(
        "relative border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors",
        isDragging
          ? "border-accent-blue bg-accent-blue-dim/20"
          : loadedFile
          ? "border-accent-green bg-accent-green-dim/10"
          : "border-border hover:border-border-strong bg-surface-2",
        className
      )}
      onClick={() => inputRef.current?.click()}
      onDragEnter={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDragOver={(e) => e.preventDefault()}
      onDrop={handleDrop}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={handleChange}
        onClick={(e) => (e.currentTarget.value = "")}
      />

      {loadedFile ? (
        <div className="flex flex-col items-center gap-2">
          <File size={24} className="text-accent-green" />
          <p className="text-sm font-medium text-text-primary mono">{loadedFile}</p>
          <p className="text-xs text-text-muted">Click to replace</p>
        </div>
      ) : (
        <div className="flex flex-col items-center gap-2">
          <Upload size={24} className="text-text-muted" />
          <p className="text-sm font-medium text-text-primary">{label}</p>
          {description && <p className="text-xs text-text-muted">{description}</p>}
          <p className="text-xs text-text-muted mt-1">Drag & drop or click to browse</p>
        </div>
      )}
    </div>
  );
}
