#include "StdAfx.h"
#include "Capture.h"


Capture::Capture()
{
	this->src_dc = NULL;
	this->capture_dc = NULL;
	this->capture_bitmap = NULL;
	this->cursor_captured = false;
	cursor_info.cbSize = sizeof(CURSORINFO);




}


Capture::~Capture()
{


}

CAPTURE_RETURN Capture::PartialInit(const Monitor& monitor, bool capture_cursor)
{
	this->capture_cursor = 0;
	this->monitor = monitor;
	this->src_dc = CreateDCA(monitor.name, NULL, NULL, NULL);
	if (this->src_dc == NULL) {
		//OutputDebugString(" CreateDC(monitor.name, NULL, NULL, NULL) => null");
		return CREATEDC_FAILED;
	}

	this->capture_dc = CreateCompatibleDC(this->src_dc);

	 memdc = CreateCompatibleDC(this->src_dc);//创建兼容屏幕的内存DC
	 memdc1 = CreateCompatibleDC(this->src_dc);
	if (this->capture_dc == NULL) {
		DeleteDC(this->src_dc);
		//OutputDebugString("capture_dc => null");
		return  CREATEDC_FAILED;
	}

	this->capture_bitmap = CreateCompatibleBitmap(this->src_dc, monitor.capture_w, monitor.capture_h);
	if (this->capture_bitmap == NULL) {
		DeleteDC(this->src_dc);
		DeleteDC(this->capture_dc);
	//	OutputDebugString("capture_bitmap => null");
		return  CREATEDC_FAILED;
	}

	//select object
	this->old_bmp = SelectObject(this->capture_dc, this->capture_bitmap);

	this->capture_cursor = capture_cursor;

	this->capt_rect.left = monitor.capture_x;
	this->capt_rect.top = monitor.capture_y;

	this->capt_rect.right = monitor.capture_x + monitor.capture_w;
	this->capt_rect.bottom = monitor.capture_y + monitor.capture_h;

	memset(&bi, 0, sizeof(bi));
	bi.biSize = sizeof(BITMAPINFOHEADER);

	bi.biWidth = monitor.capture_w;
	bi.biHeight = -monitor.capture_h;//负数
	bi.biPlanes = 1;
	bi.biBitCount = 32;//(BGRA) always 32 bits
	bi.biCompression = BI_RGB;
	bi.biSizeImage =
		((monitor.capture_w * bi.biBitCount + 31) / 32) * 4

		* monitor.width;
	return  RETURN_SUCCESS;
}

void Capture::PartialFree()
{
	SelectObject(this->capture_dc, this->old_bmp);

	if (this->capture_bitmap != NULL) {
		DeleteObject(this->capture_bitmap);
	}

	if (this->capture_dc != NULL) {
		DeleteDC(this->capture_dc);
	}

	if (this->src_dc != NULL) {
		DeleteDC(this->src_dc);
	}
	if (this->memdc != NULL) {
		DeleteDC(this->memdc);
	}
	if (this->memdc1 != NULL) {
		DeleteDC(this->memdc1);
	}

}

CAPTURE_RETURN Capture::PartialProcessFrame(void* frame_buffer)
{
	if (BitBlt(capture_dc, 0, 0,monitor.capture_w, monitor.capture_h, this->src_dc, monitor.capture_x, monitor.capture_y,SRCCOPY ) == FALSE)
		return  BITBLT_FAILED;

	if (this->capture_cursor) {
		memset(&cursor_info, 0, sizeof(CURSORINFO));
		cursor_info.cbSize = sizeof(CURSORINFO);
		cursor_captured = GetCursorInfo(&cursor_info);

		if (cursor_captured) {

			//在这个范围内
			if (PtInRect(&this->capt_rect, cursor_info.ptScreenPos)) {

				HICON      icon;
				ICONINFO   ii;
				icon = CopyIcon(cursor_info.hCursor);
				if (GetIconInfo(icon, &ii)) {

					SelectObject(memdc, ii.hbmMask);//白底黑鼠标
					SelectObject(memdc1, ii.hbmColor);//黑底彩色鼠标
					BitBlt(capture_dc, cursor_info.ptScreenPos.x - (int)ii.xHotspot - monitor.capture_x, cursor_info.ptScreenPos.y - (int)ii.yHotspot - monitor.capture_y, 20, 20, memdc, 0, 0, SRCAND);
					BitBlt(capture_dc, cursor_info.ptScreenPos.x - (int)ii.xHotspot - monitor.capture_x, cursor_info.ptScreenPos.y - (int)ii.yHotspot - monitor.capture_y,20, 20, memdc1, 0, 0, SRCPAINT);//将带有鼠标的屏幕位图抓取
				/*	DrawIconEx(capture_dc,
						cursor_info.ptScreenPos.x - (int)ii.xHotspot - monitor.capture_x,
						cursor_info.ptScreenPos.y - (int)ii.yHotspot - monitor.capture_y
						, icon, 0, 0, 0, NULL,
						DI_NORMAL);*/

					DeleteObject(ii.hbmColor);
					DeleteObject(ii.hbmMask);
				}

				DestroyIcon(icon);
			}
		}
	}
	if (GetDIBits(this->src_dc, this->capture_bitmap, 0, (UINT)monitor.capture_h,frame_buffer, (BITMAPINFO *)&bi, DIB_RGB_COLORS) != monitor.capture_h)
	{
		return  BITBLT_FAILED;
	}

	return RETURN_SUCCESS;
}