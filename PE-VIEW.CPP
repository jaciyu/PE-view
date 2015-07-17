/* designed by netfairy
*  time 2015/7/17
*/

#include<stdio.h>
#include<windows.h>
int main(int argv,char * argc[])
{
	//变量的定义
	int i;
	int nSecNum;  //节区的数目
	BOOL ret=FALSE;  //判断变量
	HANDLE hFile;  //文件句柄
	HANDLE hMap;  //映像句柄
	LPVOID hBase;  //映像基址指针


	PIMAGE_DOS_HEADER hDos;  //DOS头指针
	PIMAGE_NT_HEADERS hNt;  //NT头指针
	PIMAGE_SECTION_HEADER hSection;  //节表指针
	
	hFile=CreateFile(argc[1],GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);  //打开文件
	if(hFile==INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL,"打开文件失败","警告",1);
		return ret;
	}
	hMap=CreateFileMapping(hFile,NULL,PAGE_READWRITE | SEC_IMAGE,0,0,0);  //载入映像
	if(hMap==NULL)
	{
		MessageBox(NULL,"载入映像失败","警告",1);
		CloseHandle(hFile);  //关闭文件句柄
		return ret;
	}
	hBase=MapViewOfFile(hMap,FILE_MAP_READ | FILE_MAP_WRITE,0,0,0);
	if(hBase==NULL)
	{
		MessageBox(NULL,"载入映像失败","警告",1);
		CloseHandle(hFile);  //关闭文件句柄
		CloseHandle(hMap);  //关闭映像句柄
		return ret;
	}

//////////////////////////////////////////////////////////////////////////////
//接下来判断是否为有效的PE文件	只用上面的hBase值											
/////////////////////////////////////////////////////////////////////////////
	hDos=(PIMAGE_DOS_HEADER)hBase;  //指向DOS头
	if(hDos->e_magic!=IMAGE_DOS_SIGNATURE)  
	{
		MessageBox(NULL,"这不是有效的PE文件","警告",1);
		return ret;
	}
	hNt=(PIMAGE_NT_HEADERS)((DWORD)hBase+hDos->e_lfanew);  //指向NT头
	if(hNt->Signature!=IMAGE_NT_SIGNATURE)
	{
		MessageBox(NULL,"这不是有效的PE文件","警告",1);
		return ret;
	}
	hSection=(PIMAGE_SECTION_HEADER)((DWORD)&(hNt->OptionalHeader)+hNt->FileHeader.SizeOfOptionalHeader);  //指向节表头

/////////////////////////////////////////////////////////////////////////////////////////////////
//接下来读取PE信息
//////////////////////////////////////////////////////////////////////////////////////////////////
	printf("PE文件的基地址是:%08X\n",hNt->OptionalHeader.ImageBase);
	printf("PE文件的入口点地址是:%08X\n",hNt->OptionalHeader.AddressOfEntryPoint);
	printf("PE文件的内存对齐值是:%08x\n",hNt->OptionalHeader.SectionAlignment);
	printf("PE文件的文件对齐值是:%08x\n",hNt->OptionalHeader.FileAlignment);
	printf("PE文件的节区数目是:%04x\n",hNt->FileHeader.NumberOfSections);
	printf("PE文件的可选头大小为:%04x\n",hNt->FileHeader.SizeOfOptionalHeader);
	printf("PE文件数据目录表个数:%08x\n",hNt->OptionalHeader.NumberOfRvaAndSizes);
	printf("\n");
	//下面枚举节表
	nSecNum=hNt->FileHeader.NumberOfSections;
	for(i=0;i<nSecNum;i++)
	{
		printf("节区名:%s\n",hSection[i].Name);
		printf("虚拟地址:%08x\n",hSection[i].VirtualAddress);
		printf("虚拟大小:%08x\n",hSection[i].Misc);
		printf("Raw地址；%08x\n",hSection[i].PointerToRawData);
		printf("Raw大小:%08x\n",hSection[i].SizeOfRawData);
		printf("节区属性:%08x\n",hSection[i].Characteristics);
		printf("\n");
	}

	printf("请按任意键退出...");
	if(getchar())
	{
	ret=TRUE;  //否则返回真
	}
	return ret;
}
