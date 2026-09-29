import axios from 'axios';
import {
  ButtonView,
  FileDialogButtonView,
  FileRepository,
  IconFileUpload,
  Plugin,
  type Editor,
  type FileLoader,
  type UploadAdapter,
} from 'ckeditor5';

import apiClient, { getApiErrorMessage } from '../../api/client';
import type { UploadResponse } from '../../types';

const ALLOWED_FILE_TYPES = [
  '.7z',
  '.avi',
  '.csv',
  '.doc',
  '.docx',
  '.flv',
  '.gif',
  '.gz',
  '.gzip',
  '.jpeg',
  '.jpg',
  '.mov',
  '.mp3',
  '.mp4',
  '.mpc',
  '.mpeg',
  '.mpg',
  '.ods',
  '.odt',
  '.pdf',
  '.png',
  '.ppt',
  '.pptx',
  '.ps',
  '.pxd',
  '.rar',
  '.rtf',
  '.tar',
  '.tgz',
  '.txt',
  '.vsd',
  '.wav',
  '.wma',
  '.wmv',
  '.xls',
  '.xlsx',
  '.xml',
  '.zip',
];

type UploadKind = 'image' | 'file';

function normalizeUploadError(error: unknown) {
  if (axios.isCancel(error)) return '上传已取消';
  return getApiErrorMessage(error, '上传失败，请稍后再试');
}

async function uploadEditorFile(
  kind: UploadKind,
  file: File,
  onProgress?: (loaded: number, total?: number) => void,
  signal?: AbortSignal,
) {
  const formData = new FormData();
  formData.append('upload', file);

  const { data } = await apiClient.post<UploadResponse>(`/upload/${kind}`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    signal,
    onUploadProgress: (event) => {
      onProgress?.(event.loaded, event.total);
    },
  });

  if (!data.url) {
    throw new Error('上传响应缺少文件地址');
  }
  return data;
}

class LegacyImageUploadAdapter implements UploadAdapter {
  private controller = new AbortController();

  constructor(private readonly loader: FileLoader) {}

  async upload() {
    const file = await this.loader.file;
    if (!file) {
      throw new Error('没有可上传的图片');
    }

    const uploaded = await uploadEditorFile(
      'image',
      file,
      (loaded, total) => {
        this.loader.uploaded = loaded;
        if (total) {
          this.loader.uploadTotal = total;
        }
      },
      this.controller.signal,
    );

    return { default: uploaded.url };
  }

  abort() {
    this.controller.abort();
  }
}

export class LegacyImageUploadAdapterPlugin extends Plugin {
  static get requires() {
    return [FileRepository] as const;
  }

  static get pluginName() {
    return 'LegacyImageUploadAdapterPlugin' as const;
  }

  init() {
    const fileRepository = this.editor.plugins.get(FileRepository);
    fileRepository.createUploadAdapter = (loader) => new LegacyImageUploadAdapter(loader);
  }
}

async function insertUploadedFileLink(editor: Editor, file: File) {
  try {
    const uploaded = await uploadEditorFile('file', file);
    editor.model.change((writer) => {
      const linkedText = writer.createText(uploaded.filename || file.name, {
        linkHref: uploaded.url,
      });
      editor.model.insertContent(linkedText);
    });
  } catch (error) {
    window.alert(normalizeUploadError(error));
  }
}

export class LegacyFileUploadPlugin extends Plugin {
  static get pluginName() {
    return 'LegacyFileUploadPlugin' as const;
  }

  init() {
    const editor = this.editor;

    editor.ui.componentFactory.add('legacyFileUpload', (locale) => {
      const view = new FileDialogButtonView(locale);

      view.set({
        acceptedType: ALLOWED_FILE_TYPES.join(','),
        allowMultipleFiles: false,
        icon: IconFileUpload,
        label: editor.t('Insert file'),
        tooltip: true,
      });

      view.on('done', (_event, files) => {
        const file = (files as FileList).item(0);
        if (file) {
          void insertUploadedFileLink(editor, file);
        }
      });

      return view;
    });
  }
}

export class LightweightFormulaPlugin extends Plugin {
  static get pluginName() {
    return 'LightweightFormulaPlugin' as const;
  }

  init() {
    const editor = this.editor;

    editor.ui.componentFactory.add('insertFormula', (locale) => {
      const view = new ButtonView(locale);

      view.set({
        label: 'f(x)',
        tooltip: '插入 LaTeX 公式',
        withText: true,
      });

      view.on('execute', () => {
        const input = window.prompt('输入 LaTeX 公式（不需要输入分隔符）');
        const equation = input?.trim();
        if (!equation) return;

        const display = window.confirm('插入为独立公式？\n确定：独立公式\n取消：行内公式');
        const content = display ? `\\[ ${equation} \\]` : `\\( ${equation} \\)`;

        editor.model.change((writer) => {
          editor.model.insertContent(writer.createText(content));
        });
      });

      return view;
    });
  }
}
