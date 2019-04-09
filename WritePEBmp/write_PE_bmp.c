#include <stdio.h>
#include "al_write_PE_bmp.h"


write_PE_error write_PE_error_num;

//If your compiler doesn't have min(int a, int b) built in, uncomment the code below.
/*int min(int a, int b)
{
	if(a>b)
		return b;
	return a;
}*/

int pack_bmp_pe(const char *pefilename, const char *bmpfilename, uint32_t id)
{

	ALLEGRO_FILE *BMP_file;

	uint32_t bmp_file_size;

	write_PE_error_num = NO_ERROR_PRESENT;

	BMP_file = al_fopen(bmpfilename, "rb");
	if (!BMP_file) {
		write_PE_error_num = BMP_FILE_NOT_FOUND;
		return -1;
	}

	bmp_file_size = (uint32_t)al_fsize(BMP_file);

	uint8_t *buffer = malloc(bmp_file_size);
	if (!buffer) {
		write_PE_error_num = MALLOC_FAILURE;
		return -1;
	}

	al_fseek(BMP_file, 0, ALLEGRO_SEEK_SET);
	if (al_fread(BMP_file, buffer, bmp_file_size) != bmp_file_size) {
		write_PE_error_num = BMP_FILE_INVALID;
		return -1;
	}

	if (buffer[0] != 0x42 || buffer[1] != 0x4D)
	{
		write_PE_error_num = BMP_FILE_INVALID;
		return -1;
	}

	al_fclose(BMP_file);

	if (add_pefile_bmp_resource(pefilename, buffer + 0x0E, bmp_file_size - 0x0E, id) != 0){
		free(buffer);
		return -1;
	}

	free(buffer);
	
	return 0;
}

int add_pefile_bmp_resource(const char *filename, const uint8_t* buffer, uint32_t buffer_size, uint32_t id)
{
	ALLEGRO_BITMAP *bmp = NULL;
	ALLEGRO_FILE *PE_file;
	ALLEGRO_FILE *PE_tempfile;
	ALLEGRO_PATH *temp_path = 0;
	int n, m, VirtualRawDiff, bmp_present, ID_located, rsrc_located;
	AL_IMAGE_DOS_HEADER DOS_header;
	char PE_signature[4];
	AL_IMAGE_FILE_HEADER PE_header;
	AL_IMAGE_SECTION_HEADER section_header;

	AL_BITMAPINFOHEADER bmp_header;

	uint32_t read_size;
	uint8_t read_buffer[1024];

	PE_file = al_fopen(filename, "rb+");
	if (!PE_file) {
		PE_file = al_fopen("peprototype.egf", "rb+");
		if (!PE_file) {
			write_PE_error_num = PE_FILE_NOT_FOUND;
			return -1;
		}
	}

	PE_tempfile = al_fopen("~egf.tmp", "wb+");
	if (!PE_tempfile) {
		write_PE_error_num = MALLOC_FAILURE;
		al_fclose(PE_file);
		return -1;
	}

	while (true)
	{
		read_size = al_fread(PE_file, read_buffer, 1024);
		if (read_size == 0)
			break;
		al_fwrite(PE_tempfile, read_buffer, read_size);
	}

	al_fflush(PE_tempfile);
	al_fseek(PE_file, 0, ALLEGRO_SEEK_SET);
	al_fseek(PE_tempfile, 0, ALLEGRO_SEEK_SET);

	DOS_header = read_DOS_header(PE_tempfile);
	al_fseek(PE_tempfile, DOS_header.e_lfanew, ALLEGRO_SEEK_SET);
	for (n = 0; n < 4; n++) {

		PE_signature[n] = al_fgetc(PE_tempfile);

	}

	if (strcmp(PE_signature, "PE") != 0) {

		write_PE_error_num = NO_PE_HEADER;
		al_fclose(PE_tempfile);
		al_fclose(PE_file);
		remove("~egf.tmp");
		return -1;
	}

	PE_header = read_PE_header(PE_tempfile);

	al_fseek(PE_tempfile, PE_header.SizeOfOptionalHeader, ALLEGRO_SEEK_CUR);

	rsrc_located = 0;
	for (n = 0; n < PE_header.NumberOfSections; n++) {

		section_header = read_section_header(PE_tempfile);
		if (strcmp((char*)section_header.Name, ".rsrc") == 0) {

			rsrc_located = 1;
			break;

		}

	}

	if (!rsrc_located) {

		write_PE_error_num = RSRC_NOT_LOCATED;
		al_fclose(PE_tempfile);
		al_fclose(PE_file);
		remove("~egf.tmp");
		return -1;
	}

	VirtualRawDiff = section_header.VirtualAddress - section_header.PointerToRawData;

	al_fseek(PE_tempfile, section_header.PointerToRawData, ALLEGRO_SEEK_SET);

	res_header header;

	header.root = read_rsrc_directory(PE_tempfile);
	header.entry_name_nums = 0;
	header.l1 = malloc(sizeof(L1_data) * (header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries));
	if (!header.l1) {

		write_PE_error_num = MALLOC_FAILURE;
		al_fclose(PE_tempfile);
		al_fclose(PE_file);
		remove("~egf.tmp");
		return -1;

	}

	for (n = 0; n < header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries; n++) {

		header.l1[n].entry = read_rsrc_dir_entry(PE_tempfile);
	}

	bmp_present = -1;
	ID_located = -1;

	for (n = 0; n < header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries; n++) {

		al_fseek(PE_tempfile, (section_header.PointerToRawData + (header.l1[n].entry.OffsetToData - 0x80000000)), ALLEGRO_SEEK_SET);

		header.l1[n].l2.directory = read_rsrc_directory(PE_tempfile);
		header.l1[n].l2.resource_identifier = malloc(sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * (header.l1[n].l2.directory.NumberOfNamedEntries + header.l1[n].l2.directory.NumberOfIdEntries));
		header.l1[n].l3.directory = malloc(sizeof(AL_IMAGE_RESOURCE_DIRECTORY) * (header.l1[n].l2.directory.NumberOfNamedEntries + header.l1[n].l2.directory.NumberOfIdEntries));
		header.l1[n].l3.resource_language = malloc(sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * (header.l1[n].l2.directory.NumberOfNamedEntries + header.l1[n].l2.directory.NumberOfIdEntries));
		header.l1[n].entry_leaf.leaf = malloc(sizeof(AL_IMAGE_RESOURCE_DATA_ENTRY) * (header.l1[n].l2.directory.NumberOfNamedEntries + header.l1[n].l2.directory.NumberOfIdEntries));

		if (header.l1[n].entry.Name == 2) {

			bmp_present = n;
		}

		for (m = 0; m < header.l1[n].l2.directory.NumberOfNamedEntries + header.l1[n].l2.directory.NumberOfIdEntries; m++) {
			header.l1[n].l2.resource_identifier[m] = read_rsrc_dir_entry(PE_tempfile);
		}

		if ((header.l1[n].entry.Name & 0x80000000) != 0)
		{
			al_fseek(PE_tempfile, (section_header.PointerToRawData + (header.l1[n].entry.Name - 0x80000000)), ALLEGRO_SEEK_SET);

			uint16_t str_len = al_fread16le(PE_tempfile);
			al_fread(PE_tempfile, header.entry_name[header.entry_name_nums], str_len * 2);
			header.entry_name[header.entry_name_nums][str_len] = 0;
			header.entry_name_len[header.entry_name_nums] = str_len;

			header.l1[n].entry.Name = 0x80000000 | header.entry_name_nums;
			header.entry_name_nums++;
		}

		for (m = 0; m < header.l1[n].l2.directory.NumberOfNamedEntries + header.l1[n].l2.directory.NumberOfIdEntries; m++) {

			if ((header.l1[n].l2.resource_identifier[m].Name & 0x80000000) != 0)
			{
				al_fseek(PE_tempfile, (section_header.PointerToRawData + (header.l1[n].l2.resource_identifier[m].Name - 0x80000000)), ALLEGRO_SEEK_SET);

				uint16_t str_len = al_fread16le(PE_tempfile);
				al_fread(PE_tempfile, header.entry_name[header.entry_name_nums], str_len * 2);
				header.entry_name[header.entry_name_nums][str_len] = 0;
				header.entry_name_len[header.entry_name_nums] = str_len;

				header.l1[n].l2.resource_identifier[m].Name = 0x80000000 | header.entry_name_nums;
				header.entry_name_nums++;
			}

			al_fseek(PE_tempfile, (section_header.PointerToRawData + (header.l1[n].l2.resource_identifier[m].OffsetToData - 0x80000000)), ALLEGRO_SEEK_SET);
			header.l1[n].l3.directory[m] = read_rsrc_directory(PE_tempfile);
			header.l1[n].l3.resource_language[m] = read_rsrc_dir_entry(PE_tempfile);

			al_fseek(PE_tempfile, (section_header.PointerToRawData + (header.l1[n].l3.resource_language[m].OffsetToData & 0x7FFFFFFF)), ALLEGRO_SEEK_SET);
			header.l1[n].entry_leaf.leaf[m] = read_data_entry(PE_tempfile);

			if (bmp_present == n && header.l1[n].l2.resource_identifier[m].Name == id) {
				ID_located = m;
			}
		}
	}

	if (bmp_present == -1)
	{
		L1_data *pNewL1Data = malloc(sizeof(L1_data) * (header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries + 1));
		memset(pNewL1Data, 0, sizeof(L1_data) * (header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries + 1));
		memcpy(pNewL1Data, header.l1, sizeof(L1_data) * (header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries));
		free(header.l1);
		header.l1 = pNewL1Data;
		bmp_present = header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries;
		header.l1[bmp_present].entry.Name = 2;
		header.root.NumberOfIdEntries ++;
	}

	if (ID_located == -1) {
		uint32_t entryNums = header.l1[bmp_present].l2.directory.NumberOfNamedEntries + header.l1[bmp_present].l2.directory.NumberOfIdEntries;
		AL_IMAGE_RESOURCE_DIRECTORY_ENTRY *pNewDirEntry = malloc(sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * (entryNums + 1));
		memset(pNewDirEntry, 0, sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * (entryNums + 1));
		memcpy(pNewDirEntry, header.l1[bmp_present].l2.resource_identifier, sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * entryNums);
		free(header.l1[bmp_present].l2.resource_identifier);
		header.l1[bmp_present].l2.resource_identifier = pNewDirEntry;
		header.l1[bmp_present].l2.resource_identifier[entryNums].Name = id;

		AL_IMAGE_RESOURCE_DIRECTORY *pNewDir = malloc(sizeof(AL_IMAGE_RESOURCE_DIRECTORY) * (entryNums + 1));
		memset(pNewDir, 0, sizeof(AL_IMAGE_RESOURCE_DIRECTORY) * (entryNums + 1));
		memcpy(pNewDir, header.l1[bmp_present].l3.directory, sizeof(AL_IMAGE_RESOURCE_DIRECTORY) * entryNums);
		free(header.l1[bmp_present].l3.directory);
		header.l1[bmp_present].l3.directory = pNewDir;
		header.l1[bmp_present].l3.directory[entryNums].NumberOfIdEntries = 1;

		pNewDirEntry = malloc(sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * (entryNums + 1));
		memset(pNewDirEntry, 0, sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * (entryNums + 1));
		memcpy(pNewDirEntry, header.l1[bmp_present].l3.resource_language, sizeof(AL_IMAGE_RESOURCE_DIRECTORY_ENTRY) * entryNums);
		free(header.l1[bmp_present].l3.resource_language);
		header.l1[bmp_present].l3.resource_language = pNewDirEntry;

		AL_IMAGE_RESOURCE_DATA_ENTRY *pNewResDataEntry = malloc(sizeof(AL_IMAGE_RESOURCE_DATA_ENTRY) * (entryNums + 1));
		memset(pNewResDataEntry, 0, sizeof(AL_IMAGE_RESOURCE_DATA_ENTRY) * (entryNums + 1));
		memcpy(pNewResDataEntry, header.l1[bmp_present].entry_leaf.leaf, sizeof(AL_IMAGE_RESOURCE_DATA_ENTRY) * entryNums);
		free(header.l1[bmp_present].entry_leaf.leaf);
		header.l1[bmp_present].entry_leaf.leaf = pNewResDataEntry;
		header.l1[bmp_present].entry_leaf.leaf[entryNums].Size = buffer_size;

		header.l1[bmp_present].l2.directory.NumberOfIdEntries ++;
		ID_located = entryNums;
	}
	else {
		header.l1[bmp_present].entry_leaf.leaf[ID_located].Size = buffer_size;
	}

	al_fseek(PE_tempfile, DOS_header.e_lfanew + 0x38, ALLEGRO_SEEK_SET);
	uint32_t sectionAlign = al_fread32le(PE_tempfile);
	uint32_t fileAlign = al_fread32le(PE_tempfile);


	al_fclose(PE_file);
	PE_file = al_fopen(filename, "wb+");

	al_fseek(PE_tempfile, 0, ALLEGRO_SEEK_SET);
	uint32_t remainSize = section_header.PointerToRawData;
	while (remainSize > 0)
	{
		read_size = al_fread(PE_tempfile, read_buffer, min(1024, remainSize));
		if (read_size == 0)
			break;
		remainSize -= read_size;
		al_fwrite(PE_file, read_buffer, read_size);
	}

	// Write Resource
	uint32_t rsrcSectionRealSize = 0;

	write_rsrc_directory(PE_file, header.root);

	for (n = 0; n < header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries; n++) {

		header.l1[n].entry.OffsetToData = 0x80000000 | get_l2_offset(&header, n);
		if ((header.l1[n].entry.Name & 0x80000000) != 0) {
			header.l1[n].entry.Name = 0x80000000 | get_name_offset(&header, header.l1[n].entry.Name & 0x7FFFFFFF);
		}
		write_rsrc_dir_entry(PE_file, header.l1[n].entry);
	}

	for (n = 0; n < header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries; n++) {

		write_rsrc_directory(PE_file, header.l1[n].l2.directory);
		for (m = 0; m < header.l1[n].l2.directory.NumberOfNamedEntries + header.l1[n].l2.directory.NumberOfIdEntries; m++) {
			header.l1[n].l2.resource_identifier[m].OffsetToData = 0x80000000 | (get_l3_offset(&header, n) + m * 0x18);
			if ((header.l1[n].l2.resource_identifier[m].Name & 0x80000000) != 0) {
				header.l1[n].l2.resource_identifier[m].Name = 0x80000000 | get_name_offset(&header, header.l1[n].l2.resource_identifier[m].Name & 0x7FFFFFFF);
			}
			write_rsrc_dir_entry(PE_file, header.l1[n].l2.resource_identifier[m]);
		}
	}

	for (n = 0; n < header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries; n++) {
		for (m = 0; m < header.l1[n].l2.directory.NumberOfNamedEntries + header.l1[n].l2.directory.NumberOfIdEntries; m++) {
			write_rsrc_directory(PE_file, header.l1[n].l3.directory[m]);
			if ((header.l1[n].l3.resource_language[m].OffsetToData & 0x80000000) != 0)
				header.l1[n].l3.resource_language[m].OffsetToData = 0x80000000 | (get_leaf_offset(&header, n) + m * 0x10);
			else
				header.l1[n].l3.resource_language[m].OffsetToData = (get_leaf_offset(&header, n) + m * 0x10);
			write_rsrc_dir_entry(PE_file, header.l1[n].l3.resource_language[m]);
		}
	}

	for (n = 0; n < header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries; n++) {
		for (m = 0; m < header.l1[n].l2.directory.NumberOfNamedEntries + header.l1[n].l2.directory.NumberOfIdEntries; m++) {
			AL_IMAGE_RESOURCE_DATA_ENTRY temp = header.l1[n].entry_leaf.leaf[m];
			temp.OffsetToData = section_header.VirtualAddress + get_raw_offset(&header, n, m);
			write_data_entry(PE_file, temp);
		}
	}

	for (n = 0; n < (int)header.entry_name_nums; n++) {
		al_fwrite16le(PE_file, header.entry_name_len[n]);
		al_fwrite(PE_file, header.entry_name[n], (header.entry_name_len[n]+1)*2);
	}

	uint32_t base = get_name_offset(&header, header.entry_name_nums);
	uint32_t baseAlign = (base - 1) / 0x10 + 1;
	baseAlign *= 0x10;

	for (n = 0; n < (int)(baseAlign - base) / 2; n++)
		al_fwrite16le(PE_file, 0);

	base = baseAlign;

	for (n = 0; n < header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries; n++) {
		for (m = 0; m < header.l1[n].l2.directory.NumberOfNamedEntries + header.l1[n].l2.directory.NumberOfIdEntries; m++) {

			if (bmp_present == n && header.l1[n].l2.resource_identifier[m].Name == id) {
				al_fwrite(PE_file, buffer, buffer_size);
				base += buffer_size;
			}
			else {

				al_fseek(PE_tempfile, header.l1[n].entry_leaf.leaf[m].OffsetToData - VirtualRawDiff, ALLEGRO_SEEK_SET);
				remainSize = header.l1[n].entry_leaf.leaf[m].Size;

				base += remainSize;

				while (remainSize > 0)
				{
					read_size = al_fread(PE_tempfile, read_buffer, min(1024, remainSize));
					if (read_size == 0)
						break;
					remainSize -= read_size;
					al_fwrite(PE_file, read_buffer, read_size);
				}

			}
		}
	}

	baseAlign = (base - 1) / fileAlign + 1;
	baseAlign *= fileAlign;

	for (n = 0; n < (int)(baseAlign - base); n++)
		al_fputc(PE_file, 0);

	uint32_t vaAlign = (base - 1) / sectionAlign + 1;
	vaAlign *= sectionAlign;

	AL_IMAGE_SECTION_HEADER etc_section_header;
	al_fseek(PE_tempfile, DOS_header.e_lfanew + 0x8C, ALLEGRO_SEEK_SET);
	uint32_t orgBase = al_fread32le(PE_tempfile);

	uint32_t orgBaseAlign = section_header.SizeOfRawData;
	uint32_t orgVAAlign = (orgBase - 1) / sectionAlign + 1;
	orgVAAlign *= sectionAlign;

	uint32_t dirRAV;
	uint32_t dirSize;
	al_fseek(PE_file, DOS_header.e_lfanew + 0x78, ALLEGRO_SEEK_SET);
	al_fseek(PE_tempfile, DOS_header.e_lfanew + 0x78, ALLEGRO_SEEK_SET);
	for (n = 0; n < (PE_header.SizeOfOptionalHeader - 0x78) / 8; n++){
		dirRAV = al_fread32le(PE_tempfile);
		dirSize = al_fread32le(PE_tempfile);
		if (dirRAV > section_header.VirtualAddress) {
			al_fwrite32le(PE_file, dirRAV + vaAlign - orgVAAlign);
			al_fseek(PE_file, 4, ALLEGRO_SEEK_CUR);
		} else if (dirRAV == section_header.VirtualAddress) {
			al_fseek(PE_file, 4, ALLEGRO_SEEK_CUR);
			al_fwrite32le(PE_file, base);
		} else  {
			al_fseek(PE_file, 8, ALLEGRO_SEEK_CUR);
		}
	}
	
	al_fseek(PE_file, DOS_header.e_lfanew + 0x18, ALLEGRO_SEEK_SET);
	al_fseek(PE_file, PE_header.SizeOfOptionalHeader, ALLEGRO_SEEK_CUR);
	al_fseek(PE_tempfile, DOS_header.e_lfanew + 0x18, ALLEGRO_SEEK_SET);
	al_fseek(PE_tempfile, PE_header.SizeOfOptionalHeader, ALLEGRO_SEEK_CUR);

	for (n = 0; n < PE_header.NumberOfSections; n++) {

		etc_section_header = read_section_header(PE_tempfile);

		if (etc_section_header.VirtualAddress > section_header.VirtualAddress) {
			al_fseek(PE_file, 0x0C, ALLEGRO_SEEK_CUR);
			al_fwrite32le(PE_file, etc_section_header.VirtualAddress + vaAlign - orgVAAlign);
			al_fseek(PE_file, 0x18, ALLEGRO_SEEK_CUR);
		}
		else if (etc_section_header.VirtualAddress == section_header.VirtualAddress) {
			al_fseek(PE_file, 0x08, ALLEGRO_SEEK_CUR);
			al_fwrite32le(PE_file, base);
			al_fseek(PE_file, 0x1C, ALLEGRO_SEEK_CUR);
		}
		else {
			al_fseek(PE_file, 0x28, ALLEGRO_SEEK_CUR);
		}
	}

	al_fseek(PE_file, DOS_header.e_lfanew + 0x18, ALLEGRO_SEEK_SET);
	al_fseek(PE_file, PE_header.SizeOfOptionalHeader, ALLEGRO_SEEK_CUR);
	al_fseek(PE_tempfile, DOS_header.e_lfanew + 0x18, ALLEGRO_SEEK_SET);
	al_fseek(PE_tempfile, PE_header.SizeOfOptionalHeader, ALLEGRO_SEEK_CUR);

	for (n = 0; n < PE_header.NumberOfSections; n++) {

		etc_section_header = read_section_header(PE_tempfile);

		if (etc_section_header.PointerToRawData > section_header.PointerToRawData) {
			al_fseek(PE_file, 0x14, ALLEGRO_SEEK_CUR);
			al_fwrite32le(PE_file, etc_section_header.PointerToRawData + baseAlign - orgBaseAlign);
			al_fseek(PE_file, 0x10, ALLEGRO_SEEK_CUR);
		}
		else if (etc_section_header.PointerToRawData == section_header.PointerToRawData) {
			al_fseek(PE_file, 0x10, ALLEGRO_SEEK_CUR);
			al_fwrite32le(PE_file, baseAlign);
			al_fseek(PE_file, 0x14, ALLEGRO_SEEK_CUR);
		}
		else {
			al_fseek(PE_file, 0x28, ALLEGRO_SEEK_CUR);
		}
	}

	base = (etc_section_header.VirtualAddress + etc_section_header.VirtualSize);
	base = base + vaAlign - orgVAAlign;
	baseAlign = (base - 1) / sectionAlign + 1;
	baseAlign *= sectionAlign;

	al_fseek(PE_file, DOS_header.e_lfanew + 0x50, ALLEGRO_SEEK_SET);
	al_fwrite32le(PE_file, vaAlign);

	al_fseek(PE_tempfile, DOS_header.e_lfanew + 0x20, ALLEGRO_SEEK_SET);
	baseAlign = al_fread32le(PE_tempfile);
	baseAlign = baseAlign + vaAlign - orgVAAlign;
	al_fseek(PE_file, DOS_header.e_lfanew + 0x20, ALLEGRO_SEEK_SET);
	al_fwrite32le(PE_file, baseAlign);
	
	al_fflush(PE_file);
	al_fclose(PE_tempfile);
	al_fclose(PE_file);

	remove("~egf.tmp");

	for (n = 0; n < header.root.NumberOfNamedEntries + header.root.NumberOfIdEntries; n++) {

		free(header.l1[n].l2.resource_identifier);
		free(header.l1[n].l3.directory);
		free(header.l1[n].l3.resource_language);
		free(header.l1[n].entry_leaf.leaf);
	}

	free(header.l1);

	return 0;
}

uint32_t get_l1_offset(res_header* res, uint32_t id)
{
	return 0x10 + id * 8;
}

uint32_t get_l2_offset(res_header* res, uint32_t id)
{
	uint32_t base = 0x10 + (res->root.NumberOfNamedEntries + res->root.NumberOfIdEntries) * 8;

	for (uint32_t i = 0; i < id; i++)
	{
		base += 0x10;
		base += (res->l1[i].l2.directory.NumberOfNamedEntries + res->l1[i].l2.directory.NumberOfIdEntries) * 8;
	}

	return base;
}

uint32_t get_l3_offset(res_header* res, uint32_t id)
{
	uint32_t base = get_l2_offset(res, res->root.NumberOfNamedEntries + res->root.NumberOfIdEntries);
	
	for (uint32_t i = 0; i < id; i++)
	{
		base += (res->l1[i].l2.directory.NumberOfNamedEntries + res->l1[i].l2.directory.NumberOfIdEntries) * 0x18;
	}

	return base;
}

uint32_t get_leaf_offset(res_header* res, uint32_t id)
{
	uint32_t base = get_l3_offset(res, res->root.NumberOfNamedEntries + res->root.NumberOfIdEntries);

	for (uint32_t i = 0; i < id; i++)
	{
		base += (res->l1[i].l2.directory.NumberOfNamedEntries + res->l1[i].l2.directory.NumberOfIdEntries) * 0x10;
	}

	return base;
}


uint32_t get_name_offset(res_header* res, uint32_t id)
{
	uint32_t base = get_leaf_offset(res, res->root.NumberOfNamedEntries + res->root.NumberOfIdEntries);

	for (uint32_t i = 0; i < id; i++)
	{
		base += (res->entry_name_len[i] + 2) * 2;
	}

	return base;
}

uint32_t get_raw_offset(res_header* res, uint32_t id, uint32_t id2)
{
	uint32_t base = get_name_offset(res, res->entry_name_nums);

	base = (base - 1) / 0x10 + 1;
	base *= 0x10;

	for (uint32_t i = 0; i < id; i++)
	{
		for (uint32_t j = 0; j < (int)res->l1[i].l2.directory.NumberOfNamedEntries + res->l1[i].l2.directory.NumberOfIdEntries; j++)
			base += res->l1[i].entry_leaf.leaf[j].Size;
	}

	for (uint32_t j = 0; j < id2; j++)
		base += res->l1[id].entry_leaf.leaf[j].Size;

	return base;
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

void write_rsrc_directory(ALLEGRO_FILE *f, AL_IMAGE_RESOURCE_DIRECTORY dir) {
	
	al_fwrite32le(f, dir.Characteristics);
	al_fwrite32le(f, dir.TimeDateStamp);
	al_fwrite16le(f, dir.MajorVersion);
	al_fwrite16le(f, dir.MinorVersion);
	al_fwrite16le(f, dir.NumberOfNamedEntries);
	al_fwrite16le(f, dir.NumberOfIdEntries);
}

void write_rsrc_dir_entry(ALLEGRO_FILE *f, AL_IMAGE_RESOURCE_DIRECTORY_ENTRY dirEnttry) {

	al_fwrite32le(f, dirEnttry.Name);
	al_fwrite32le(f, dirEnttry.OffsetToData);

}

void write_data_entry(ALLEGRO_FILE *f, AL_IMAGE_RESOURCE_DATA_ENTRY dataEntry) {
	
	 al_fwrite32le(f, dataEntry.OffsetToData);
	 al_fwrite32le(f, dataEntry.Size);
	 al_fwrite32le(f, dataEntry.CodePage);
	 al_fwrite32le(f, dataEntry.Reserved);
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
//    FILE *out = fopen("out.txt", "w");

    al_set_target_bitmap(bmp);

    for (y = 0; y < height; y++) {

        for (x = 0; x < width; x++) {

            c = al_fread16le(f);
            r = (c >> 10 & 0x001f) * 8;
            g = (c >> 5 & 0x001f) * 8;
            b = (c & 0x001f) * 8;

//            fprintf(out, "Pixel @ (%d, %d) has a value of %d (RGB %d, %d, %d)\n", x, y, c, r, g, b);
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

            r = al_fgetc(f);
            g = al_fgetc(f);
            b = al_fgetc(f);

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

            r = al_fgetc(f);
            g = al_fgetc(f);
            b = al_fgetc(f);
            al_fgetc(f);

            al_put_pixel(x, height - y - 1, al_map_rgb(r, g, b));

        }

    }

}


char* write_PE_bmp_error() {

    switch (write_PE_error_num) {

        case NO_ERROR_PRESENT       : return "No error.";
        case PE_FILE_NOT_FOUND      : return "Specified PE file and PE Prototype file could not be found.";
		case PE_FILE_INVALID		: return "Specified PE file is invalid.";
		case BMP_FILE_NOT_FOUND		: return "Specified BMP file could not be found.";
		case BMP_FILE_INVALID		: return "Specified BMP file is invalid.";
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
	if (argc < 4) {
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


	if (pack_bmp_pe(argv[1], argv[2], atol(argv[3])) != 0){
		abort_example("Error writing image - %s", write_PE_bmp_error());
	}

	return 0;
}

