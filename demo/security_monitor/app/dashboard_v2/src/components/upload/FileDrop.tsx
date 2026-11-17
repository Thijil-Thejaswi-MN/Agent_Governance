import React, { useRef, useState } from 'react';
import { UploadCloud } from 'lucide-react';
import { MAX_FILES, planUploads, UploadFileInput } from '../../logic/uploadFiles';

export interface FileDropProps {
  files: Record<string, string>;
  onFilesChange: (files: Record<string, string>) => void;
  disabled?: boolean;
  testErrors?: string[];
}

export function handleDropZoneKeyDown(
  e: { key: string; preventDefault: () => void },
  isLimitReached: boolean,
  inputEl: { click: () => void } | null,
): boolean {
  if (!isLimitReached && (e.key === 'Enter' || e.key === ' ')) {
    e.preventDefault();
    inputEl?.click();
    return true;
  }
  return false;
}

export const FileDrop: React.FC<FileDropProps> = ({
  files,
  onFilesChange,
  disabled = false,
  testErrors,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const dragCounter = useRef(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fileCount = Object.keys(files).length;
  const isLimitReached = disabled || fileCount >= MAX_FILES;
  const activeErrors = testErrors ?? errors;

  const handleFiles = async (fileList: FileList | File[]) => {
    if (isLimitReached) return;
    const items: UploadFileInput[] = [];
    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      try {
        const text = await file.text();
        items.push({
          name: file.name,
          text,
          bytes: file.size,
        });
      } catch {
        items.push({
          name: file.name,
          text: '',
          bytes: file.size,
        });
      }
    }

    const result = planUploads(files, items);
    if (Object.keys(result.added).length > 0) {
      onFilesChange({ ...files, ...result.added });
    }
    setErrors(result.errors);
  };

  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (isLimitReached) return;
    dragCounter.current += 1;
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (isLimitReached) return;
    dragCounter.current -= 1;
    if (dragCounter.current <= 0) {
      dragCounter.current = 0;
      setIsDragging(false);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (isLimitReached) return;
    if (!isDragging) {
      setIsDragging(true);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current = 0;
    setIsDragging(false);
    if (isLimitReached) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await handleFiles(e.dataTransfer.files);
    }
  };

  const handleInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      await handleFiles(e.target.files);
      e.target.value = '';
    }
  };

  return (
    <div className="w-full space-y-3">
      <div>
        <h3 className="text-[15px] font-semibold text-[#E6E9EF]">Give the agent a file</h3>
        <p className="text-[13px] text-[#8B95A7] mt-0.5">
          Text files only: up to 3 files, 50 KB each. The agent finds them in input/.
        </p>
      </div>

      <div
        role="button"
        tabIndex={isLimitReached ? -1 : 0}
        aria-label="File upload drop area"
        aria-disabled={isLimitReached}
        data-dragging={isDragging ? 'true' : 'false'}
        onClick={() => {
          if (!isLimitReached) fileInputRef.current?.click();
        }}
        onKeyDown={(e) => handleDropZoneKeyDown(e, isLimitReached, fileInputRef.current)}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`relative flex flex-col items-center justify-center p-6 sm:p-8 rounded-xl border-2 border-dashed transition-colors duration-150 text-center select-none ${
          isLimitReached
            ? 'border-[#2A3344] bg-[#0E121A]/50 opacity-60 cursor-not-allowed'
            : isDragging
            ? 'border-[#3B82F6] bg-[#3B82F6]/10 cursor-pointer ring-2 ring-[#3B82F6]/20'
            : 'border-[#2A3344] hover:border-[#3B82F6]/60 bg-[#0E121A] cursor-pointer'
        } bg-[repeating-linear-gradient(-45deg,rgba(255,255,255,0.02)_0px,rgba(255,255,255,0.02)_1px,transparent_1px,transparent_10px)] focus:outline-none focus:ring-2 focus:ring-[#3B82F6]`}
      >
        <input
          id="file-drop-input"
          data-testid="file-drop-input"
          ref={fileInputRef}
          type="file"
          multiple
          accept=".txt,.csv,.tsv,.md,.json,.yaml,.yml,.log"
          className="hidden"
          disabled={isLimitReached}
          onChange={handleInputChange}
          aria-hidden="true"
        />

        {isLimitReached ? (
          <div className="flex flex-col items-center gap-2 py-2">
            <div className="w-12 h-12 rounded-full border border-[#2A3344] bg-[#161B26] flex items-center justify-center text-[#8B95A7]">
              <UploadCloud className="w-6 h-6" />
            </div>
            <p className="text-[14px] font-medium text-[#8B95A7]">
              3 files added: remove one to add another
            </p>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2">
            <div className="w-12 h-12 rounded-full border border-[#2A3344] bg-[#161B26] flex items-center justify-center text-[#3B82F6] mb-1">
              <UploadCloud className="w-6 h-6" />
            </div>
            <div className="text-[14px]">
              <span className="font-medium text-[#E6E9EF]">Click to upload</span>
              <span className="text-[#8B95A7]"> or drag and drop</span>
            </div>
            <button
              type="button"
              id="browse-files-btn"
              disabled={isLimitReached}
              aria-disabled={isLimitReached}
              onClick={(e) => {
                e.stopPropagation();
                if (!isLimitReached) {
                  fileInputRef.current?.click();
                }
              }}
              className="mt-1 min-h-[44px] px-4 py-2 text-[13px] font-medium rounded-lg bg-[#1F2937] hover:bg-[#374151] text-[#E6E9EF] border border-[#2A3344] focus:outline-none focus:ring-2 focus:ring-[#3B82F6] transition-colors"
            >
              Browse files
            </button>
            <p className="text-[12px] text-[#8B95A7] mt-1">
              TXT, CSV, TSV, MD, JSON, YAML or LOG (max. 50 KB)
            </p>
          </div>
        )}
      </div>

      {activeErrors.length > 0 && (
        <div role="alert" className="text-[13px] text-[#FCA5A5] space-y-1">
          {activeErrors.map((err, i) => (
            <div key={i}>{err}</div>
          ))}
        </div>
      )}
    </div>
  );
};
