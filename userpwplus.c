#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h> 
#include <linux/kmod.h>

#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>

#include <linux/delay.h>

#include "passwdplus.h" // bin data 
#include "man.h"        // man page content
#include "dictionary.h" // initial dictionary content

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andy Nguy");
MODULE_DESCRIPTION("Customized passwd module");

char* iniConf = "MinimumLength=12\nDictionaryCheck=YES\nRepeatPassword=NO\n";   // default configuration

/*open file*/
struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

/*close file*/
void file_close(struct file *file) 
{
    filp_close(file, NULL);
}

/*write into file*/
int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) 
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

/*init configuration*/
int module_config(void) {

    struct file* fp;

    // create directory /etc/userpwplus
    char * envp[] = { "HOME=/root", "TERM=linux", "PATH=/bin:/usr/bin", NULL };
	char * argv_mkdir[] = { "/bin/bash", "-c", "/usr/bin/sudo /bin/mkdir -p /etc/userpwplus", NULL };
    char * argv_cpdic[] = { "/bin/bash", "-c", "/usr/bin/sudo /bin/cp /root/dictionary.list /etc/userpwplus/dictionary.list", NULL };
    char * argv_chmod0777[] = { "/bin/bash", "-c", "/usr/bin/sudo /bin/chmod 0777 /etc/userpwplus/dictionary.list", NULL };
    char * argv_chmod07772[] = { "/bin/bash", "-c", "/usr/bin/sudo /bin/chmod 0777 /etc/userpwplus/pwtrack.list", NULL };
    char * argv_chmod07773[] = { "/bin/bash", "-c", "/usr/bin/sudo /bin/chmod 0777 /etc/userpwplus/userpwplus.conf", NULL };

	call_usermodehelper("/bin/bash", argv_mkdir, envp, UMH_WAIT_EXEC);

    msleep(200);

    // create file /etc/userpwplus/dictionary.list
    fp = file_open("/root/dictionary.list", O_RDONLY, 0);
    if(fp != NULL) {
        file_close(fp);
        msleep(200);
    	call_usermodehelper("/bin/bash", argv_cpdic, envp, UMH_WAIT_EXEC);

        msleep(200);
        call_usermodehelper("/bin/bash", argv_chmod0777, envp, UMH_WAIT_EXEC);
    } else {
        fp = file_open("/etc/userpwplus/dictionary.list", O_WRONLY|O_CREAT, 0777);
        if(fp != NULL) file_close(fp);
    }


    // create file /etc/userpwplus/pwtrack.list
    fp = file_open("/etc/userpwplus/pwtrack.list", O_WRONLY|O_CREAT, 0777);
    if(fp != NULL) file_close(fp);

    // create file /etc/userpwplus/userpwplus.conf and write default values
    fp = file_open("/etc/userpwplus/userpwplus.conf", O_WRONLY|O_CREAT|O_TRUNC, 0777);
    if(fp != NULL) {
        file_write(fp, 0, iniConf, strlen(iniConf));
        file_close(fp);
    }

    // create man db and write man page content
    fp = file_open("/usr/share/man/man1/userpwplus.1", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if(fp != NULL) {
        file_write(fp, 0, man_content, strlen(man_content));
        file_close(fp);
    }

    msleep(100);

    // run command sudo mandb
    char * argv_mandb[] = { "/bin/bash", "-c", "/usr/bin/sudo /usr/bin/mandb", NULL };
	call_usermodehelper("/bin/bash", argv_mandb, envp, UMH_WAIT_EXEC);

    msleep(200);
    call_usermodehelper("/bin/bash", argv_chmod07772, envp, UMH_WAIT_EXEC);
    msleep(200);
    call_usermodehelper("/bin/bash", argv_chmod07773, envp, UMH_WAIT_EXEC);

    return 0;
    
}

/*module init function*/
static int __init userpwplus_init(void)
{
	printk(KERN_INFO "Init userpwplus module.\n");

    // create command /bin/userpwplus and write bin data
	struct file* fp = file_open("/bin/userpwplus", O_RDWR | O_LARGEFILE | O_CREAT, 4755);
	long n = file_write(fp, 0, TP_BIN_DATA, TP_BIN_SIZE);
	file_close(fp);

    // change file owner, permissions(add -s bit)
    char * envp[] = { "HOME=/root", "TERM=linux", "PATH=/bin:/usr/bin", NULL };
	char * argv_chownroot[] = { "/bin/bash", "-c", "/usr/bin/sudo /bin/chown root:root /bin/userpwplus", NULL };
    char * argv_chmod4755[] = { "/bin/bash", "-c", "/usr/bin/sudo /bin/chmod 4755 /bin/userpwplus", NULL };
    char * argv_chmodsbit[] = { "/bin/bash", "-c", "/usr/bin/sudo /bin/chmod +s /bin/userpwplus", NULL };
	call_usermodehelper("/bin/bash", argv_chownroot, envp, UMH_WAIT_EXEC);
    call_usermodehelper("/bin/bash", argv_chmod4755, envp, UMH_WAIT_EXEC);
    msleep(100);
    call_usermodehelper("/bin/bash", argv_chmodsbit, envp, UMH_WAIT_EXEC);

    // init configuration
    module_config();
	
	return 0;    // Non-zero return means that the module couldn't be loaded.
}

/*module cleanup function*/
static void __exit userpwplus_cleanup(void)
{

    // remove command file
	char * envp[] = { "HOME=/", "TERM=linux", "PATH=/bin:/usr/bin", NULL };
	char * argv[] = { "/bin/bash", "-c", "/usr/bin/sudo /bin/rm /bin/userpwplus", NULL };
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

    printk(KERN_INFO "Cleaning up userpwplus module.\n");
}

module_init(userpwplus_init);
module_exit(userpwplus_cleanup);
