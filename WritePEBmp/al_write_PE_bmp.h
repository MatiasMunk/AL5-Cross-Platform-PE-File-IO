#ifndef STRUCT_H
#define STRUCT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <allegro5/allegro5.h>
#include <allegro5/allegro_image.h>


	typedef enum {

		NO_ERROR_PRESENT,
		PE_FILE_NOT_FOUND,
		PE_FILE_INVALID,
		BMP_FILE_NOT_FOUND,
		BMP_FILE_INVALID,
		NO_PE_HEADER,
		RSRC_NOT_LOCATED,
		BMPS_NOT_LOCATED,
		ID_NOT_FOUND,
		CREATE_BITMAP_FAILURE,
		MALLOC_FAILURE

	} write_PE_error;


	typedef struct _AL_IMAGE_DOS_HEADER {

		uint16_t e_magic;
		uint16_t e_cblp;
		uint16_t e_cp;
		uint16_t e_crlc;
		uint16_t e_cparhdr;
		uint16_t e_minalloc;
		uint16_t e_maxalloc;
		uint16_t e_ss;
		uint16_t e_sp;
		uint16_t e_csum;
		uint16_t e_ip;
		uint16_t e_cs;
		uint16_t e_lfarlc;
		uint16_t e_ovno;
		uint16_t e_res[4];
		uint16_t e_oemid;
		uint16_t e_oeminfo;
		uint16_t e_res2[10];
		uint32_t e_lfanew;

	} AL_IMAGE_DOS_HEADER;


	typedef struct _AL_IMAGE_FILE_HEADER {

		uint16_t  Machine;
		uint16_t  NumberOfSections;
		uint32_t  TimeDateStamp;
		uint32_t  PointerToSymbolTable;
		uint32_t  NumberOfSymbols;
		uint16_t  SizeOfOptionalHeader;
		uint16_t  Characteristics;

	} AL_IMAGE_FILE_HEADER;


	typedef struct _AL_IMAGE_SECTION_HEADER {

		unsigned char   Name[8];
		uint32_t   VirtualSize;
		uint32_t   VirtualAddress;
		uint32_t   SizeOfRawData;
		uint32_t   PointerToRawData;
		uint32_t   PointerToRelocations;
		uint32_t   PointerToLinenumbers;
		uint16_t   NumberOfRelocations;
		uint16_t   NumberOfLinenumbers;
		uint32_t   Characteristics;

	} AL_IMAGE_SECTION_HEADER;


	typedef struct _AL_IMAGE_RESOURCE_DIRECTORY {

		uint32_t  Characteristics;
		uint32_t  TimeDateStamp;
		uint16_t  MajorVersion;
		uint16_t  MinorVersion;
		uint16_t  NumberOfNamedEntries;
		uint16_t  NumberOfIdEntries;

	} AL_IMAGE_RESOURCE_DIRECTORY;


	typedef struct _AL_IMAGE_RESOURCE_DIRECTORY_ENTRY {

		uint32_t  Name;
		uint32_t  OffsetToData;

	} AL_IMAGE_RESOURCE_DIRECTORY_ENTRY;


	typedef struct _AL_IMAGE_RESOURCE_DATA_ENTRY {

		uint32_t  OffsetToData;
		uint32_t  Size;
		uint32_t  CodePage;
		uint32_t  Reserved;

	} AL_IMAGE_RESOURCE_DATA_ENTRY;




	typedef struct al_tagBITMAPINFOHEADER {

		uint32_t biSize;
		uint32_t biWidth;
		uint32_t biHeight;
		uint16_t biPlanes;
		uint16_t biBitCount;
		uint32_t biCompression;
		uint32_t biSizeImage;
		uint32_t biXPelsPerMeter;
		uint32_t biYPelsPerMeter;
		uint32_t biClrUsed;
		uint32_t biClrImportant;

	} AL_BITMAPINFOHEADER;


	typedef struct _L2_data {

		AL_IMAGE_RESOURCE_DIRECTORY directory;
		AL_IMAGE_RESOURCE_DIRECTORY_ENTRY *resource_identifier;

	} L2_data;


	typedef struct _L3_data {

		AL_IMAGE_RESOURCE_DIRECTORY *directory;
		AL_IMAGE_RESOURCE_DIRECTORY_ENTRY *resource_language;

	} L3_data;


	typedef struct _leaf_node {

		AL_IMAGE_RESOURCE_DATA_ENTRY *leaf;

	} leaf_node;

	typedef struct _L1_data {

		AL_IMAGE_RESOURCE_DIRECTORY_ENTRY entry;
		L2_data l2;
		L3_data l3;
		leaf_node entry_leaf;
	} L1_data;

	typedef struct _res_header {
		AL_IMAGE_RESOURCE_DIRECTORY root;
		L1_data *l1;
	
		wchar_t entry_name[100][20];
		uint16_t entry_name_len[100];
		uint32_t entry_name_nums;
	} res_header;


	int add_pefile_bmp_resource(const char *filename, const uint8_t* buffer, uint32_t buffer_size, uint32_t id);
	int pack_bmp_pe(const char *pefilename, const char *bmpfilename, uint32_t id);

	uint32_t get_l1_offset(res_header* res, uint32_t id);
	uint32_t get_l2_offset(res_header* res, uint32_t id);
	uint32_t get_l3_offset(res_header* res, uint32_t id);
	uint32_t get_leaf_offset(res_header* res, uint32_t id);
	uint32_t get_name_offset(res_header* res, uint32_t id);
	uint32_t get_raw_offset(res_header* res, uint32_t id, uint32_t id2);

	AL_IMAGE_DOS_HEADER read_DOS_header(ALLEGRO_FILE *f);
	AL_IMAGE_FILE_HEADER read_PE_header(ALLEGRO_FILE *f);
	AL_IMAGE_SECTION_HEADER read_section_header(ALLEGRO_FILE *f);
	AL_IMAGE_RESOURCE_DIRECTORY read_rsrc_directory(ALLEGRO_FILE *f);
	AL_IMAGE_RESOURCE_DIRECTORY_ENTRY read_rsrc_dir_entry(ALLEGRO_FILE *f);
	AL_IMAGE_RESOURCE_DATA_ENTRY read_data_entry(ALLEGRO_FILE *f);

	void write_rsrc_directory(ALLEGRO_FILE *f, AL_IMAGE_RESOURCE_DIRECTORY dir);
	void write_rsrc_dir_entry(ALLEGRO_FILE *f, AL_IMAGE_RESOURCE_DIRECTORY_ENTRY dirEnttry);
	void write_data_entry(ALLEGRO_FILE *f, AL_IMAGE_RESOURCE_DATA_ENTRY dataEntry);

	AL_BITMAPINFOHEADER read_bmp_header(ALLEGRO_FILE *f);
	int load_DIB(ALLEGRO_BITMAP *bmp, int depth, ALLEGRO_FILE *f);
	void load_DIB_16(ALLEGRO_BITMAP *bmp, ALLEGRO_FILE *f);
	void load_DIB_24(ALLEGRO_BITMAP *bmp, ALLEGRO_FILE *f);
	void load_DIB_32(ALLEGRO_BITMAP *bmp, ALLEGRO_FILE *f);
	char *write_PE_bmp_error();


	extern write_PE_error write_PE_error_num;

#ifdef __cplusplus
}
#endif

#endif
