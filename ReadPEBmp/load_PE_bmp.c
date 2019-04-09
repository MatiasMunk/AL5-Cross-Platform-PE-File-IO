#include <stdio.h>
#include "al_load_PE_bmp.h"


load_PE_error load_PE_error_num;


ALLEGRO_BITMAP *load_PE_bmp(const char *filename, int ID) {

    ALLEGRO_BITMAP *bmp = NULL;
    ALLEGRO_FILE *PE_file;
    int n, VirtualRawDiff, entries, bmp_present, ID_located, bmp_start, rsrc_located;
    AL_IMAGE_DOS_HEADER DOS_header;
    char PE_signature[4];
    AL_IMAGE_FILE_HEADER PE_header;
    AL_IMAGE_SECTION_HEADER section_header;
    AL_IMAGE_RESOURCE_DIRECTORY root;
    AL_IMAGE_RESOURCE_DIRECTORY_ENTRY *root_entries;
    L2_data L2_entries;
    L3_data L3_entries;
    leaf_node leaf_entries;
    AL_BITMAPINFOHEADER bmp_header;

    load_PE_error_num = NO_ERROR_PRESENT;

    PE_file = al_fopen(filename, "rb");
    if (!PE_file) {

        load_PE_error_num = FILE_NOT_FOUND;
        return NULL;

    }


    DOS_header = read_DOS_header(PE_file);
    al_fseek(PE_file, DOS_header.e_lfanew, ALLEGRO_SEEK_SET);
    for (n = 0; n < 4; n++) {

        PE_signature[n] = al_fgetc(PE_file);

    }
    printf("\n");
    if (strcmp(PE_signature, "PE") != 0) {

        load_PE_error_num = NO_PE_HEADER;
        return NULL;

    }

    PE_header = read_PE_header(PE_file);

    al_fseek(PE_file, PE_header.SizeOfOptionalHeader, ALLEGRO_SEEK_CUR);

    rsrc_located = 0;
    for (n = 0; n < PE_header.NumberOfSections; n++) {

        section_header = read_section_header(PE_file);
        if (strcmp((char*)section_header.Name, ".rsrc") == 0) {

            rsrc_located = 1;
            break;

        }

    }
    if (!rsrc_located) {

        load_PE_error_num = RSRC_NOT_LOCATED;
        return NULL;

    }

    VirtualRawDiff = section_header.VirtualAddress - section_header.PointerToRawData;

    al_fseek(PE_file, section_header.PointerToRawData, ALLEGRO_SEEK_SET);
    root = read_rsrc_directory(PE_file);

    root_entries = malloc(sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * (root.NumberOfNamedEntries + root.NumberOfIdEntries));
    if (!root_entries) {

        load_PE_error_num = MALLOC_FAILURE;
        return NULL;

    }

    for (n = 0; n < root.NumberOfNamedEntries + root.NumberOfIdEntries; n++) {

        root_entries[n] = read_rsrc_dir_entry(PE_file);

    }

    bmp_present = -1;
    for (n = 0; n < root.NumberOfNamedEntries + root.NumberOfIdEntries; n++) {

        if (root_entries[n].Name == 2) {

            bmp_present = n;
            break;

        }

    }
    if (bmp_present == -1) {

        load_PE_error_num = BMPS_NOT_LOCATED;
        return NULL;

    }

    al_fseek(PE_file, (section_header.PointerToRawData + (root_entries[n].OffsetToData - 0x80000000)), ALLEGRO_SEEK_SET);

    L2_entries.directory = read_rsrc_directory(PE_file);

    entries = L2_entries.directory.NumberOfNamedEntries + L2_entries.directory.NumberOfIdEntries;
    L2_entries.resource_identifier = malloc(sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * entries);

    for (n = 0; n < entries; n++) {

        L2_entries.resource_identifier[n] = read_rsrc_dir_entry(PE_file);

    }

    L3_entries.directory = malloc(sizeof(AL_IMAGE_RESOURCE_DIRECTORY) * entries);
    L3_entries.resource_language = malloc(sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * entries);

    for (n = 0; n < entries; n++) {

        al_fseek(PE_file, (section_header.PointerToRawData + (L2_entries.resource_identifier[n].OffsetToData - 0x80000000)), ALLEGRO_SEEK_SET);

        L3_entries.directory[n] = read_rsrc_directory(PE_file);
        L3_entries.resource_language[n] = read_rsrc_dir_entry(PE_file);

    }

    leaf_entries.leaf = malloc(sizeof(AL_IMAGE_RESOURCE_DATA_ENTRY) * entries);

    for (n = 0; n < entries; n++) {

        al_fseek(PE_file, (section_header.PointerToRawData + L3_entries.resource_language[n].OffsetToData), ALLEGRO_SEEK_SET);

        leaf_entries.leaf[n] = read_data_entry(PE_file);

    }

    ID_located = 0;
    for (n = 0; n < entries; n++) {

        if (L2_entries.resource_identifier[n].Name == ID) {

            bmp_start = leaf_entries.leaf[n].OffsetToData - VirtualRawDiff;
            ID_located = 1;
            break;

        }
    }
    if (ID_located == 0) {

        load_PE_error_num = ID_NOT_FOUND;
        return NULL;

    }

    al_fseek(PE_file, bmp_start, ALLEGRO_SEEK_SET);
    bmp_header = read_bmp_header(PE_file);

    al_set_new_bitmap_flags(ALLEGRO_MEMORY_BITMAP);
    bmp = al_create_bitmap(bmp_header.biWidth, bmp_header.biHeight);
    if (!bmp) {

        load_PE_error_num = CREATE_BITMAP_FAILURE;
        return NULL;

    }

    load_DIB(bmp, bmp_header.biBitCount, PE_file);

    free(root_entries);
    free(L2_entries.resource_identifier);
    free(L3_entries.resource_language);
    free(leaf_entries.leaf);

    return bmp;

}


AL_IMAGE_DOS_HEADER read_DOS_header(ALLEGRO_FILE *f) {

    AL_IMAGE_DOS_HEADER temp;
    int n;

    temp.e_magic = al_fread16le(f);
    temp.e_cblp = al_fread16le(f);
    temp.e_cp = al_fread16le(f);
    temp.e_crlc = al_fread16le(f);
    temp.e_cparhdr = al_fread16le(f);
    temp.e_minalloc = al_fread16le(f);
    temp.e_maxalloc = al_fread16le(f);
    temp.e_ss = al_fread16le(f);
    temp.e_sp = al_fread16le(f);
    temp.e_csum = al_fread16le(f);
    temp.e_ip = al_fread16le(f);
    temp.e_cs = al_fread16le(f);
    temp.e_lfarlc = al_fread16le(f);
    temp.e_ovno = al_fread16le(f);
    for (n = 0; n < 4; n++) {

        temp.e_res[n] = al_fread16le(f);

    }
    temp.e_oemid = al_fread16le(f);
    temp.e_oeminfo = al_fread16le(f);
    for (n = 0; n < 10; n++) {

        temp.e_res2[n] = al_fread16le(f);

    }
    temp.e_lfanew = al_fread32le(f);

    return temp;

}


AL_IMAGE_FILE_HEADER read_PE_header(ALLEGRO_FILE *f) {

    AL_IMAGE_FILE_HEADER temp;

    temp.Machine = al_fread16le(f);
    temp.NumberOfSections = al_fread16le(f);
    temp.TimeDateStamp = al_fread32le(f);
    temp.PointerToSymbolTable = al_fread32le(f);
    temp.NumberOfSymbols = al_fread32le(f);
    temp.SizeOfOptionalHeader = al_fread16le(f);
    temp.Characteristics = al_fread16le(f);

    return temp;

}


AL_IMAGE_SECTION_HEADER read_section_header(ALLEGRO_FILE *f) {

    AL_IMAGE_SECTION_HEADER temp;
    int n;

    for (n = 0; n < 8; n++) {

        temp.Name[n] = al_fgetc(f);

    }
    temp.VirtualSize = al_fread32le(f);
    temp.VirtualAddress = al_fread32le(f);
    temp.SizeOfRawData = al_fread32le(f);
    temp.PointerToRawData = al_fread32le(f);
    temp.PointerToRelocations = al_fread32le(f);
    temp.PointerToLinenumbers = al_fread32le(f);
    temp.NumberOfRelocations = al_fread16le(f);
    temp.NumberOfLinenumbers = al_fread16le(f);
    temp.Characteristics = al_fread32le(f);

    return temp;

}


AL_IMAGE_RESOURCE_DIRECTORY read_rsrc_directory(ALLEGRO_FILE *f) {

    AL_IMAGE_RESOURCE_DIRECTORY temp;

    temp.Characteristics = al_fread32le(f);
    temp.TimeDateStamp = al_fread32le(f);
    temp.MajorVersion = al_fread16le(f);
    temp.MinorVersion = al_fread16le(f);
    temp.NumberOfNamedEntries = al_fread16le(f);
    temp.NumberOfIdEntries = al_fread16le(f);

    return temp;

}


AL_IMAGE_RESOURCE_DIRECTORY_ENTRY read_rsrc_dir_entry(ALLEGRO_FILE *f) {

    AL_IMAGE_RESOURCE_DIRECTORY_ENTRY temp;

    temp.Name = al_fread32le(f);
    temp.OffsetToData = al_fread32le(f);

    return temp;

}


AL_IMAGE_RESOURCE_DATA_ENTRY read_data_entry(ALLEGRO_FILE *f) {

    AL_IMAGE_RESOURCE_DATA_ENTRY temp;

    temp.OffsetToData = al_fread32le(f);
    temp.Size = al_fread32le(f);
    temp.CodePage = al_fread32le(f);
    temp.Reserved = al_fread32le(f);

    return temp;

}


AL_BITMAPINFOHEADER read_bmp_header(ALLEGRO_FILE *f) {

    AL_BITMAPINFOHEADER temp;

    temp.biSize = al_fread32le(f);
    temp.biWidth = al_fread32le(f);
    temp.biHeight = al_fread32le(f);
    temp.biPlanes = al_fread16le(f);
    temp.biBitCount = al_fread16le(f);
    temp.biCompression = al_fread32le(f);
    temp.biSizeImage = al_fread32le(f);
    temp.biXPelsPerMeter = al_fread32le(f);
    temp.biYPelsPerMeter = al_fread32le(f);
    temp.biClrUsed = al_fread32le(f);
    temp.biClrImportant = al_fread32le(f);

    return temp;

}


int load_DIB(ALLEGRO_BITMAP *bmp, int depth, ALLEGRO_FILE *f) {

    switch (depth) {

        case 16 :   load_DIB_16(bmp, f);
                    return 0;
        case 24 :   load_DIB_24(bmp, f);
                    return 0;
        case 32 :   load_DIB_32(bmp, f);
                    return 0;
        default :   return -1;

    }

}


void load_DIB_16(ALLEGRO_BITMAP *bmp, ALLEGRO_FILE *f) {

    int x, y, c, r, g, b, width = al_get_bitmap_width(bmp), height = al_get_bitmap_height(bmp);

    al_set_target_bitmap(bmp);

    for (y = 0; y < height; y++) {

        for (x = 0; x < width; x++) {

            c = al_fread16le(f);
            r = (c >> 10 & 0x001f) * 8;
            g = (c >> 5 & 0x001f) * 8;
            b = (c & 0x001f) * 8;

            al_draw_pixel(x, height - y - 1, al_map_rgb(r, g, b));

        }

        if ((width % 2) != 0) {

            al_fread16le(f);

        }

    }

}


void load_DIB_24(ALLEGRO_BITMAP *bmp, ALLEGRO_FILE *f) {

    int x, y, n, r, g, b, width = al_get_bitmap_width(bmp), height = al_get_bitmap_height(bmp);

    al_set_target_bitmap(bmp);

    for (y = 0; y < height; y++) {

        for (x = 0; x < width; x++) {

            b = al_fgetc(f);
            g = al_fgetc(f);
            r = al_fgetc(f);

            al_put_pixel(x, height - y - 1, al_map_rgb(r, g, b));

        }

        for (n = 0; n < (width % 4); n++) {

            al_fgetc(f);

        }

    }

}


void load_DIB_32(ALLEGRO_BITMAP *bmp, ALLEGRO_FILE *f) {

    int x, y, r, g, b, width = al_get_bitmap_width(bmp), height = al_get_bitmap_height(bmp);

    al_set_target_bitmap(bmp);

    for (y = 0; y < height; y++) {

        for (x = 0; x < width; x++) {

            b = al_fgetc(f);
            g = al_fgetc(f);
            r = al_fgetc(f);
            al_fgetc(f);

            al_put_pixel(x, height - y - 1, al_map_rgb(r, g, b));

        }

    }

}


char* load_PE_bmp_error() {

    switch (load_PE_error_num) {

        case NO_ERROR_PRESENT       : return "No error.";
        case FILE_NOT_FOUND         : return "Specified file could not be found.";
        case NO_PE_HEADER           : return "Not a valid PE file.";
        case RSRC_NOT_LOCATED       : return "PE file does not contain a .rsrc section.";
        case BMPS_NOT_LOCATED       : return "PE file does not conatian any bitmap resources.";
        case ID_NOT_FOUND           : return "PE file does not contain a bitmap with the specified ID.";
        case CREATE_BITMAP_FAILURE  : return "Error allocating memory for ALLEGRO_BITMAP.";
        case MALLOC_FAILURE         : return "Error allocating memory.";
        default                     : return "";

    }

}

void abort_example(char const *format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(1);
}

int main(int argc, char* argv[])
{
	if (argc < 3) {
		/*show_usage(argv[0]);*/
		return 1;
	}

	ALLEGRO_DISPLAY *display;
	ALLEGRO_TIMER *timer;
	ALLEGRO_EVENT_QUEUE *queue;
	bool redraw = true;

	if (!al_init()) {
		abort_example("Could not init Allegro.\n");
		return 1;
	}

	al_install_mouse();
	al_install_keyboard();

	display = al_create_display(640, 480);
	if (!display) {
		abort_example("Error creating display\n");
	}

	al_set_window_title(display, "Testing al_load_PE_bmp");

	al_set_new_bitmap_flags(ALLEGRO_MEMORY_BITMAP);
	ALLEGRO_BITMAP *membitmap;
	membitmap = load_PE_bmp(argv[1], atol(argv[2]));
	if (!membitmap) {
		abort_example("Error loading image - %s", load_PE_bmp_error());
	}

	al_set_new_bitmap_flags(ALLEGRO_VIDEO_BITMAP);
	ALLEGRO_BITMAP *bitmap = al_clone_bitmap(membitmap);

	timer = al_create_timer(1.0 / 30);
	queue = al_create_event_queue();
	al_register_event_source(queue, al_get_keyboard_event_source());
	al_register_event_source(queue, al_get_display_event_source(display));
	al_register_event_source(queue, al_get_timer_event_source(timer));
	al_start_timer(timer);

	al_set_target_bitmap(al_get_backbuffer(display));

	while (1) {
		ALLEGRO_EVENT event;
		al_wait_for_event(queue, &event);
		if (event.type == ALLEGRO_EVENT_DISPLAY_CLOSE)
			break;
		if (event.type == ALLEGRO_EVENT_KEY_DOWN) {
			if (event.keyboard.keycode == ALLEGRO_KEY_ESCAPE)
				break;
		}
		if (event.type == ALLEGRO_EVENT_TIMER)
			redraw = true;

		if (redraw && al_event_queue_is_empty(queue)) {
			redraw = false;
			al_clear_to_color(al_map_rgb_f(0, 0, 0));
			al_draw_bitmap(membitmap, 0, 0, 0);
			al_flip_display();
		}
	}

	al_destroy_bitmap(bitmap);
	al_destroy_bitmap(membitmap);

	return 0;
}

