/**
 * @license Copyright (c) 2003-2022, CKSource Holding sp. z o.o. All rights reserved.
 * For licensing, see https://ckeditor.com/legal/ckeditor-oss-license
 */

const toolbarBasic = [
    [
        'Styles',
        'Format',
        'FontSize',
        'TextColor',
        'BGColor',
        '-',
        'Bold',
        'Italic',
        'Underline',
        'Strike',
        'NumberedList',
        'BulletedList',
        'JustifyLeft',
        'JustifyCenter',
        'JustifyRight',
        'JustifyBlock',
        'Outdent',
        'Indent',
        'Link',
        'Unlink',
        'Table',
        'HorizontalRule',
        'Image',
        'Smiley'
    ]
];

const toolbarFull = [
    {
        name: 'snddocument',
        items: ['Source', '-', 'Save', 'NewPage', 'DocProps', 'Preview', 'Print', '-', 'Templates']
    },
    {
        name: 'clipboard',
        items: ['Undo', 'Redo']
    },
    {
        name: 'editing',
        items: ['Find', 'Replace', '-', 'SelectAll', '-', 'SpellChecker', 'Scayt']
    },
    {

        name: 'forms',
        items: ['Form', 'Checkbox', 'Radio', 'TextField', 'Textarea', 'Select', 'Button', 'ImageButton',
            'HiddenField']
    },
    '/',
    {
        name: 'basicstyles',
        items: ['Bold', 'Italic', 'Underline', 'Strike', 'Subscript', 'Superscript', '-', 'RemoveFormat']
    },
    {

        name: 'paragraph',
        items: ['NumberedList', 'BulletedList', '-', 'Outdent', 'Indent', '-', 'Blockquote', 'CreateDiv',
            '-', 'JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock', '-', 'BidiLtr', 'BidiRtl']
    },
    {
        name: 'links',
        items: ['Link', 'Unlink', 'Anchor']
    },
    {
        name: 'insert',
        items: ['Image', 'Flash', 'Table', 'HorizontalRule', 'Smiley', 'SpecialChar', 'PageBreak', 'Iframe']
    },
    '/',
    {
        name: 'styles',
        items: ['Styles', 'Format', 'FontSize']
    },
    {
        name: 'colors',
        items: ['TextColor', 'BGColor']
    },
    {
        name: 'tools',
        items: ['Maximize', 'ShowBlocks']
    }
];

CKEDITOR.editorConfig = function( config ) {
	// Define changes to default configuration here. For example:
	// config.language = 'fr';
    config.removePlugins = ['exportpdf','image','elementspath'];
    config.toolbar = toolbarBasic;
    config.height = 200;
    config.width = '99.75%';
    config.enterMode = CKEDITOR.ENTER_BR;
    config.shiftEnterMode = CKEDITOR.ENTER_P;
    //config.skin = 'kama';
    config.toolbarCanCollapse = true;
    config.resize_enabled = false;
    config.uiColor = '#ffe5dd';
    config.language_list = ['he:Hebrew:rtl', 'pt:Portuguese', 'de:German'];
    config.removeButtons = `About,Find,Subscript,Superscript,Radio,Checkbox,TextField,Textarea,Select,Form,Button,ImageButton,HiddenField`;
};

