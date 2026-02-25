#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
void find_subdomains(const char *path){
  int ret;
  char command_subfinder[1024];
  char full_command[1024];
  char subs_path[1024];
  snprintf(subs_path, sizeof(subs_path), "%s/%s", path,"Subs.txt");
  snprintf(command_subfinder, sizeof(command_subfinder),  "subfinder -dL %s/target.txt -all --recursive -o %s", path, subs_path);
  ret = system(command_subfinder);
  if (ret != 0) {
    printf("subfinder failed!\n");
    return 1;
    }
  check_alive_subdomains(path, subs_path);
}

void js_files(const char *path){
  char command[1024];
      snprintf(command, sizeof(command),
             "cat %s/urls.txt | grep -iE '.js' | grep -ivE '.json' | sort -u | tee %s/js.txt",
             path, path);
  printf("Debug: Js command - %s", command);
  system(command);
}
void full_recon(const char *path){
  find_subdomains(path);
  char subs_path[1024];
  char full_command[1024];
  char xss_find_auto[1024];
  snprintf(subs_path, sizeof(subs_path), "%s/%s", path,"Subs.txt");
  snprintf(full_command, sizeof(full_command), "cat %s |waybackurls | tee %s/urls.txt", subs_path, path);
  system(full_command);
  snprintf(xss_find_auto, sizeof(xss_find_auto), "cat %s/urls.txt | uro | gf xss > %s/xss.txt", path, path);
  system(xss_find_auto);
}

void check_alive_subdomains(const char *path, const char *subs_path){
  char command_httpx[1024];
  snprintf(command_httpx, sizeof(command_httpx), "cat %s | httpx -o %s/AliveSubs.txt", subs_path, path);
  system(command_httpx);
}

int check_dir_exists(const char *path) {
    DIR* dir = opendir(path);
    if (dir) {
        closedir(dir);
        return 1; // exists
    } else if (ENOENT == errno) {
        return 0; // does not exist
    } else {
        perror("opendir");
        return -1; // error
    }
}

int create_dir(const char *path) {
    if (mkdir(path, 0755) != 0) {
        perror("mkdir");
        return 0; // failed
    }
    return 1; // success
}

int main(int argc, char* argv[]) {
    const char path_project[1024];
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Cannot get HOME environment variable.\n");
        return 1;
    }
    char hunt_dir[1024];
    snprintf(hunt_dir, sizeof(hunt_dir), "%s/hunt", home);

    // Check if ~/hunt exists, create if not
    if (check_dir_exists(hunt_dir) == 0) {
        printf("Directory '%s' does not exist. Creating it...\n", hunt_dir);
        if (!create_dir(hunt_dir)) {
            return 1;
        }
    } else {
        printf("Directory exists: %s\n", hunt_dir);
    }

    // Ask user for target name
    char target[256];
    printf("Enter target name to hunt: ");
    if (scanf("%255s", target) != 1) {
        fprintf(stderr, "Failed to read target.\n");
        return 1;
    }
    snprintf(path_project, sizeof(path_project), "%s/hunt/%s/",home, target);

    char target_path[1024];
    snprintf(target_path, sizeof(target_path), "%s/%s", hunt_dir, target);

    // Check if target already exists
    int exists = check_dir_exists(target_path);
    if (exists == 1) {
        printf("Target '%s' already exists inside hunt directory.\n", target);
    } else if (exists == 0) {
        printf("Target '%s' does NOT exist. Creating it...\n", target);
        if (create_dir(target_path)) {
            printf("Target '%s' created successfully!\n", target);
        } else {
            printf("Failed to create target '%s'.\n", target);
        }
    } else {
        printf("Error checking target directory.\n");
    }
    FILE *fptr;
    char read_data[100];

    // --- Writing to the file ---
    // Open the file in write mode ("w")
    char target_file[1024];
    snprintf(target_file, sizeof(target_path), "%s/%s/%s", hunt_dir, target,"target.txt");

    fptr = fopen(target_file, "w");
    if (fptr == NULL) {
        printf("Error opening file for writing!\n");
        exit(1);
    }
    fprintf(fptr, "%s", target); // Write the string to the file
    fclose(fptr); // Close the file 
    pthread_t thread1, thread2;
    if (pthread_create(&thread1, NULL, full_recon, NULL) != 0) {
      perror("Failed to create thread1");
      return 1;
    }
    pthread_join(thread1, NULL);
    if (pthread_create(&thread2, NULL, js_files, NULL) != 0) {
      perror("Failed to create thread2");
      return 1;
    }
    pthread_join(thread2, NULL);

    full_recon(path_project);
    wait(200);
    
    return 0;
}
