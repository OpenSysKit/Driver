#!/usr/bin/env node
'use strict';

// ──────────────────────────────────────────────────────────────
//  OpenSysKit 文档生成器
//  用法：node generate.js [config] [output]
//        node generate.js doc-config.json OpenSysKit_Doc.docx
// ──────────────────────────────────────────────────────────────

const fs   = require('fs');
const path = require('path');

const {
    Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
    AlignmentType, BorderStyle, WidthType, ShadingType, HeadingLevel,
    LevelFormat, PageBreak, Header, Footer, PageNumber, NumberFormat,
    TabStopType, TabStopPosition,
} = require("docx");

// ── 读取配置 ──────────────────────────────────────────────────
const configPath = process.argv[2] || path.join(__dirname, 'doc-config.json');
const outputPath = process.argv[3] || path.join(__dirname, 'OpenSysKit_Doc.docx');
const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));

// ══════════════════════════════════════════════════════════════
//  调色板 & 常量
// ══════════════════════════════════════════════════════════════
const C = {
    blue:       '1A5DB8',   // 主色：标题、表头
    lightBlue:  'EAF2FB',   // 表行间色
    accent:     '2E86DE',   // 小标题左边框
    gray:       '555555',   // 正文
    lightGray:  'F5F5F5',   // 代码块背景
    disabled:   'BB3333',   // 禁用标记
    white:      'FFFFFF',
    headerBg:   '1A3A6B',   // 深蓝表头
    divider:    'CCCCCC',
};

// A4, 2cm margins（DXA: 1cm ≈ 567 DXA）
const PAGE_W   = 11906;
const MARGIN   = 1134;   // ~2cm
const CONTENT_W = PAGE_W - MARGIN * 2;  // 9638

const FONT = 'Consolas';
const FONT_BODY = 'Microsoft YaHei';

// ══════════════════════════════════════════════════════════════
//  低级构建器
// ══════════════════════════════════════════════════════════════

function run(text, opts = {}) {
    return new TextRun({
        text,
        font:  opts.font  || FONT,
        size:  (opts.size || 10) * 2,
        bold:  opts.bold  || false,
        color: opts.color || C.gray,
        italics: opts.italic || false,
    });
}

function para(children, opts = {}) {
    return new Paragraph({
        children: Array.isArray(children) ? children : [children],
        alignment: opts.align || AlignmentType.LEFT,
        spacing: {
            before: opts.spaceBefore !== undefined ? opts.spaceBefore : 60,
            after:  opts.spaceAfter  !== undefined ? opts.spaceAfter  : 60,
            line:   opts.line || 280,
        },
        indent: opts.indent ? { left: opts.indent } : undefined,
        border: opts.border || undefined,
        tabStops: opts.tabStops || undefined,
    });
}

// 水平分隔线（段落下边框）
function divider() {
    return new Paragraph({
        children: [],
        spacing: { before: 160, after: 160 },
        border: {
            bottom: { style: BorderStyle.SINGLE, size: 4, color: C.divider, space: 1 },
        },
    });
}

// 一级标题
function h1(text) {
    return new Paragraph({
        children: [
            new TextRun({ text, font: FONT, size: 30, bold: true, color: C.blue }),
        ],
        spacing: { before: 440, after: 120 },
        border: {
            bottom: { style: BorderStyle.SINGLE, size: 8, color: C.blue, space: 4 },
        },
    });
}

// 二级标题（左侧蓝色竖条用缩进 + 边框模拟）
function h2(text, disabled = false) {
    const color = disabled ? C.disabled : C.accent;
    return new Paragraph({
        children: [
            new TextRun({ text, font: FONT, size: 22, bold: true, color }),
        ],
        spacing: { before: 260, after: 80 },
        indent: { left: 180 },
        border: {
            left: { style: BorderStyle.SINGLE, size: 12, color, space: 8 },
        },
    });
}

// 三级标题
function h3(text) {
    return new Paragraph({
        children: [
            new TextRun({ text, font: FONT, size: 18, bold: true, color: C.gray }),
        ],
        spacing: { before: 180, after: 60 },
        indent: { left: 200 },
    });
}

// 正文段落
function body(text, indent = 0) {
    return para(
        [new TextRun({ text, font: FONT_BODY, size: 20, color: C.gray })],
        { spaceBefore: 40, spaceAfter: 60, indent: indent ? indent * 360 : undefined }
    );
}

// 代码块（浅灰背景 + 左侧蓝色细线）
function code(text) {
    const lines = text.split('\n');
    return lines.map((line, i) => new Paragraph({
        children: [
            new TextRun({ text: line || ' ', font: FONT, size: 18, color: '1A1A2E' }),
        ],
        spacing: { before: i === 0 ? 80 : 0, after: i === lines.length - 1 ? 80 : 0, line: 240 },
        indent: { left: 280 },
        shading: { type: ShadingType.CLEAR, fill: C.lightGray },
        border: i === 0 ? {
            left:  { style: BorderStyle.SINGLE, size: 12, color: C.accent, space: 6 },
            top:   { style: BorderStyle.SINGLE, size: 2,  color: C.divider, space: 2 },
        } : i === lines.length - 1 ? {
            left:   { style: BorderStyle.SINGLE, size: 12, color: C.accent, space: 6 },
            bottom: { style: BorderStyle.SINGLE, size: 2,  color: C.divider, space: 2 },
        } : {
            left: { style: BorderStyle.SINGLE, size: 12, color: C.accent, space: 6 },
        },
    }));
}

// ══════════════════════════════════════════════════════════════
//  表格构建器
// ══════════════════════════════════════════════════════════════

const CELL_BORDER = {
    top:    { style: BorderStyle.SINGLE, size: 1, color: 'D0D7E0' },
    bottom: { style: BorderStyle.SINGLE, size: 1, color: 'D0D7E0' },
    left:   { style: BorderStyle.SINGLE, size: 1, color: 'D0D7E0' },
    right:  { style: BorderStyle.SINGLE, size: 1, color: 'D0D7E0' },
};
const CELL_MARGINS = { top: 60, bottom: 60, left: 120, right: 120 };

function headerCell(text, width, bgColor = C.headerBg) {
    return new TableCell({
        width:   { size: width, type: WidthType.DXA },
        borders: CELL_BORDER,
        margins: CELL_MARGINS,
        shading: { type: ShadingType.CLEAR, fill: bgColor },
        children: [new Paragraph({
            children: [new TextRun({ text, font: FONT, size: 18, bold: true, color: C.white })],
            spacing: { before: 0, after: 0 },
        })],
    });
}

function dataCell(text, width, shade = false, color = C.gray) {
    return new TableCell({
        width:   { size: width, type: WidthType.DXA },
        borders: CELL_BORDER,
        margins: CELL_MARGINS,
        shading: shade ? { type: ShadingType.CLEAR, fill: C.lightBlue } : undefined,
        children: [new Paragraph({
            children: [new TextRun({ text, font: FONT, size: 18, color })],
            spacing: { before: 0, after: 0 },
        })],
    });
}

// 字段说明表（3列：字段 / 类型 / 说明）
function fieldTable(rows) {
    const W = [2800, 2000, CONTENT_W - 4800];
    const tableRows = [
        new TableRow({
            tableHeader: true,
            children: [
                headerCell('字段', W[0]),
                headerCell('类型', W[1]),
                headerCell('说明', W[2]),
            ],
        }),
        ...rows.map((r, i) => new TableRow({
            children: [
                dataCell(r[0], W[0], i % 2 === 1),
                dataCell(r[1], W[1], i % 2 === 1, '2255AA'),
                dataCell(r[2], W[2], i % 2 === 1),
            ],
        })),
    ];
    return new Table({
        width:        { size: CONTENT_W, type: WidthType.DXA },
        columnWidths: W,
        rows:         tableRows,
    });
}

// IOCTL 总表（4列）
function ioctlTable(rows) {
    const W = [3600, 1200, 2400, CONTENT_W - 7200];
    const tableRows = [
        new TableRow({
            tableHeader: true,
            children: [
                headerCell('IOCTL 名称',   W[0]),
                headerCell('功能码',        W[1]),
                headerCell('输入结构',      W[2]),
                headerCell('说明',          W[3]),
            ],
        }),
        ...rows.map((r, i) => {
            const isDisabled = r.disabled === true;
            const nameColor  = isDisabled ? C.disabled : '1A3A6B';
            const shade      = i % 2 === 1;
            return new TableRow({
                children: [
                    dataCell(r.name,  W[0], shade, nameColor),
                    dataCell(r.code,  W[1], shade, '006622'),
                    dataCell(r.input, W[2], shade),
                    dataCell(r.desc,  W[3], shade),
                ],
            });
        }),
    ];
    return new Table({
        width:        { size: CONTENT_W, type: WidthType.DXA },
        columnWidths: W,
        rows:         tableRows,
    });
}

// 源文件清单表（2列）
function fileTable(rows) {
    const W = [3800, CONTENT_W - 3800];
    const tableRows = [
        new TableRow({
            tableHeader: true,
            children: [
                headerCell('文件',  W[0]),
                headerCell('职责',  W[1]),
            ],
        }),
        ...rows.map((r, i) => new TableRow({
            children: [
                dataCell(r[0], W[0], i % 2 === 1, '1A3A6B'),
                dataCell(r[1], W[1], i % 2 === 1),
            ],
        })),
    ];
    return new Table({
        width:        { size: CONTENT_W, type: WidthType.DXA },
        columnWidths: W,
        rows:         tableRows,
    });
}

// ══════════════════════════════════════════════════════════════
//  封面
// ══════════════════════════════════════════════════════════════
function buildCover() {
    const m = cfg.meta;
    return [
        para([], { spaceBefore: 2400, spaceAfter: 0 }),  // 顶部空白

        new Paragraph({
            children: [new TextRun({ text: m.title, font: FONT, size: 64, bold: true, color: C.blue })],
            alignment: AlignmentType.CENTER,
            spacing: { before: 0, after: 120 },
        }),
        new Paragraph({
            children: [new TextRun({ text: m.subtitle, font: FONT_BODY, size: 32, color: C.gray })],
            alignment: AlignmentType.CENTER,
            spacing: { before: 0, after: 80 },
        }),
        new Paragraph({
            children: [new TextRun({ text: m.tagline, font: FONT, size: 20, color: '888888' })],
            alignment: AlignmentType.CENTER,
            spacing: { before: 0, after: 600 },
        }),

        new Paragraph({
            children: [],
            spacing: { before: 0, after: 0 },
            border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: C.blue, space: 1 } },
        }),

        new Paragraph({
            children: [
                new TextRun({ text: `版本 ${m.version}`, font: FONT, size: 20, color: C.gray }),
                new TextRun({ text: '\t', font: FONT, size: 20 }),
                new TextRun({ text: m.date, font: FONT, size: 20, color: '888888' }),
            ],
            alignment: AlignmentType.LEFT,
            spacing: { before: 120, after: 0 },
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
        }),

        new Paragraph({ children: [new PageBreak()], spacing: { before: 0, after: 0 } }),
    ];
}

// ══════════════════════════════════════════════════════════════
//  概述
// ══════════════════════════════════════════════════════════════
function buildOverview() {
    const m = cfg.meta;
    return [
        h1('1.  概述'),
        body('OpenSysKit 是一个 Windows 内核模式驱动，面向系统分析和安全研究场景，提供一组通过 DeviceIoControl 调用的内核级操作接口。用户态程序通过打开符号链接访问驱动。'),
        para([], { spaceBefore: 80, spaceAfter: 0 }),
        h3('设备路径'),
        ...code(`NT 路径  : ${m.nt_device}\n符号链接 : ${m.symlink}\n用户态   : ${m.device}`),
        para([], { spaceBefore: 80, spaceAfter: 0 }),
        h3('平台要求'),
        body(m.platform),
        body(`编译：${m.build_req}`),
        divider(),
    ];
}

// ══════════════════════════════════════════════════════════════
//  IOCTL 总表
// ══════════════════════════════════════════════════════════════
function buildIoctlTable() {
    return [
        h1('2.  IOCTL 总表'),
        body('所有 IOCTL 均使用 METHOD_BUFFERED，DeviceType=0x8000。红色名称表示当前已禁用（返回 STATUS_NOT_SUPPORTED）。'),
        para([], { spaceBefore: 100, spaceAfter: 0 }),
        ioctlTable(cfg.ioctls),
        para([], { spaceBefore: 100, spaceAfter: 0 }),
        divider(),
    ];
}

// ══════════════════════════════════════════════════════════════
//  各功能章节
// ══════════════════════════════════════════════════════════════
function buildSections() {
    const nodes = [];
    let sectionNum = 3;

    for (const sec of cfg.sections) {
        const secDisabled = sec.disabled === true;
        nodes.push(h1(`${sectionNum}.  ${sec.title}`));
        sectionNum++;

        for (const item of sec.items) {
            nodes.push(h2(item.subtitle, secDisabled || item.disabled));

            if (item.body) {
                nodes.push(body(item.body));
            }

            if (item.fields && item.fields.length) {
                nodes.push(para([], { spaceBefore: 60, spaceAfter: 0 }));
                nodes.push(fieldTable(item.fields));
                nodes.push(para([], { spaceBefore: 40, spaceAfter: 0 }));
            }
        }

        nodes.push(divider());
    }

    return nodes;
}

// ══════════════════════════════════════════════════════════════
//  错误处理约定
// ══════════════════════════════════════════════════════════════
function buildErrorNotes(num) {
    const nodes = [
        h1(`${num}.  错误处理约定`),
    ];
    for (const note of cfg.error_notes) {
        nodes.push(new Paragraph({
            children: [new TextRun({ text: `• ${note}`, font: FONT_BODY, size: 20, color: C.gray })],
            spacing: { before: 40, after: 60 },
            indent: { left: 360, hanging: 200 },
        }));
    }
    nodes.push(divider());
    return nodes;
}

// ══════════════════════════════════════════════════════════════
//  用户态调用示例
// ══════════════════════════════════════════════════════════════
function buildExamples(num) {
    const nodes = [
        h1(`${num}.  用户态调用示例（C++）`),
    ];
    for (const ex of cfg.examples) {
        nodes.push(h3(ex.title));
        nodes.push(...code(ex.code));
        nodes.push(para([], { spaceBefore: 60, spaceAfter: 0 }));
    }
    nodes.push(divider());
    return nodes;
}

// ══════════════════════════════════════════════════════════════
//  源文件清单
// ══════════════════════════════════════════════════════════════
function buildFileList(num) {
    return [
        h1(`${num}.  源文件清单`),
        fileTable(cfg.source_files),
        para([], { spaceBefore: 100, spaceAfter: 0 }),
    ];
}

// ══════════════════════════════════════════════════════════════
//  页眉 / 页脚
// ══════════════════════════════════════════════════════════════
function buildHeader() {
    return new Header({
        children: [new Paragraph({
            children: [
                new TextRun({ text: `${cfg.meta.title}  ${cfg.meta.subtitle}`, font: FONT, size: 16, color: '888888' }),
                new TextRun({ text: '\t', font: FONT, size: 16 }),
                new TextRun({ text: cfg.meta.version, font: FONT, size: 16, color: C.blue }),
            ],
            spacing: { before: 0, after: 0 },
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
            border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: C.divider, space: 4 } },
        })],
    });
}

function buildFooter() {
    return new Footer({
        children: [new Paragraph({
            children: [
                new TextRun({ text: cfg.meta.device, font: FONT, size: 16, color: 'AAAAAA' }),
                new TextRun({ text: '\t', font: FONT, size: 16 }),
                new TextRun({ text: '第 ', font: FONT_BODY, size: 16, color: 'AAAAAA' }),
                new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 16, color: C.blue }),
                new TextRun({ text: ' 页', font: FONT_BODY, size: 16, color: 'AAAAAA' }),
            ],
            spacing: { before: 0, after: 0 },
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
            border: { top: { style: BorderStyle.SINGLE, size: 2, color: C.divider, space: 4 } },
        })],
    });
}

// ══════════════════════════════════════════════════════════════
//  主程序
// ══════════════════════════════════════════════════════════════
async function main() {
    const totalSections = cfg.sections.length;
    const errorNum  = 3 + totalSections;
    const exampleNum = errorNum + 1;
    const fileNum   = exampleNum + 1;

    const children = [
        ...buildCover(),
        ...buildOverview(),
        ...buildIoctlTable(),
        ...buildSections(),
        ...buildErrorNotes(errorNum),
        ...buildExamples(exampleNum),
        ...buildFileList(fileNum),
    ];

    const doc = new Document({
        styles: {
            default: {
                document: {
                    run: { font: FONT_BODY, size: 20, color: C.gray },
                },
            },
        },
        sections: [{
            properties: {
                page: {
                    size:   { width: PAGE_W, height: 16838 },
                    margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN },
                },
            },
            headers: { default: buildHeader() },
            footers: { default: buildFooter() },
            children,
        }],
    });

    const buffer = await Packer.toBuffer(doc);
    fs.writeFileSync(outputPath, buffer);
    console.log(`✓ 文档已生成：${outputPath}  (${Math.round(buffer.length / 1024)} KB)`);
}

main().catch(err => {
    console.error('生成失败:', err.message);
    process.exit(1);
});
