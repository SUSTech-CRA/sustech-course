import { CKEditor } from '@ckeditor/ckeditor5-react';
import {
  AutoLink,
  AutoImage,
  Autoformat,
  BlockQuote,
  Bold,
  ClassicEditor,
  Code,
  CodeBlock,
  Essentials,
  Heading,
  Image,
  ImageCaption,
  ImageInsert,
  ImageResize,
  ImageStyle,
  ImageToolbar,
  ImageUpload,
  Indent,
  Italic,
  Link,
  List,
  MediaEmbed,
  Paragraph,
  PasteFromMarkdownExperimental,
  PasteFromOffice,
  PictureEditing,
  Strikethrough,
  Table,
  TableCaption,
  TableCellProperties,
  TableProperties,
  TableToolbar,
  TextTransformation,
  Underline,
  WordCount,
} from 'ckeditor5';
import 'ckeditor5/ckeditor5.css';
import { useState } from 'react';

import {
  LegacyFileUploadPlugin,
  LegacyImageUploadAdapterPlugin,
  LightweightFormulaPlugin,
} from './ckeditorPlugins';

interface RichTextEditorProps {
  value?: string;
  onChange?: (value: string) => void;
  placeholder?: string;
}

function stripImageSizeAttributes(html: string) {
  if (!html || typeof document === 'undefined') return html;
  const template = document.createElement('template');
  template.innerHTML = html;
  template.content.querySelectorAll('img').forEach((image) => {
    image.removeAttribute('width');
    image.removeAttribute('height');
  });
  return template.innerHTML;
}

export function RichTextEditor({ value, onChange, placeholder }: RichTextEditorProps) {
  const [characters, setCharacters] = useState(0);

  return (
    <div className="rich-text-editor">
      <CKEditor
        editor={ClassicEditor}
        data={value || ''}
        config={{
          licenseKey: 'GPL',
          placeholder,
          heading: {
            options: [
              { model: 'paragraph', title: 'Paragraph', class: 'ck-heading_paragraph' },
              { model: 'heading1', view: 'h3', title: 'Heading 1', class: 'ck-heading_heading1' },
              { model: 'heading2', view: 'h4', title: 'Heading 2', class: 'ck-heading_heading2' },
              { model: 'heading3', view: 'h5', title: 'Heading 3', class: 'ck-heading_heading3' },
            ],
          },
          plugins: [
            Essentials,
            Paragraph,
            Autoformat,
            Heading,
            Bold,
            Italic,
            Underline,
            Strikethrough,
            Link,
            AutoLink,
            List,
            Code,
            CodeBlock,
            BlockQuote,
            Indent,
            MediaEmbed,
            PasteFromOffice,
            PasteFromMarkdownExperimental,
            TextTransformation,
            Table,
            TableToolbar,
            TableCaption,
            TableProperties,
            TableCellProperties,
            Image,
            ImageCaption,
            ImageStyle,
            ImageToolbar,
            ImageUpload,
            ImageInsert,
            ImageResize,
            AutoImage,
            PictureEditing,
            WordCount,
            LegacyImageUploadAdapterPlugin,
            LegacyFileUploadPlugin,
            LightweightFormulaPlugin,
          ],
          toolbar: {
            items: [
              'heading',
              '|',
              'bold',
              'italic',
              'underline',
              'strikethrough',
              'link',
              'bulletedList',
              'numberedList',
              '|',
              'outdent',
              'indent',
              '|',
              'code',
              'codeBlock',
              'uploadImage',
              'legacyFileUpload',
              'blockQuote',
              'insertTable',
              'mediaEmbed',
              '|',
              'insertFormula',
              '|',
              'undo',
              'redo',
            ],
            shouldNotGroupWhenFull: true,
          },
          image: {
            resizeOptions: [
              {
                name: 'resizeImage:original',
                value: null,
                icon: 'original',
              },
              {
                name: 'resizeImage:50',
                value: '50',
                icon: 'medium',
              },
              {
                name: 'resizeImage:75',
                value: '75',
                icon: 'large',
              },
            ],
            toolbar: [
              'imageTextAlternative',
              'toggleImageCaption',
              'resizeImage:50',
              'resizeImage:75',
              'resizeImage:original',
            ],
          },
          table: {
            tableProperties: {
              defaultProperties: {
                borderStyle: 'dashed',
                borderColor: 'hsl(0, 0%, 90%)',
                borderWidth: '3px',
                alignment: 'left',
              },
            },
            contentToolbar: [
              'tableColumn',
              'tableRow',
              'mergeTableCells',
              'toggleTableCaption',
              'tableProperties',
              'tableCellProperties',
            ],
          },
          wordCount: {
            onUpdate: (stats) => setCharacters(stats.characters),
          },
        }}
        onChange={(_event, editor) => onChange?.(stripImageSizeAttributes(editor.getData()))}
      />
      <div className="editor-word-count">字数: {characters}</div>
    </div>
  );
}
