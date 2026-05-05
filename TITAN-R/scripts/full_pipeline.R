args <- commandArgs(trailingOnly = FALSE)
fn <- grep("^--file=", args, value = TRUE)
if (!length(fn)) {
  stop("Run from project root, e.g. Rscript TITAN-R/scripts/full_pipeline.R")
}
SCRIPT_DIR <- dirname(normalizePath(sub("^--file=", "", fn[1])))
message("SCRIPT_DIR=", SCRIPT_DIR)

source(file.path(SCRIPT_DIR, "paths.R"))
message("TITAN_R_ROOT=", TITAN_R_ROOT)

source(file.path(SCRIPT_DIR, "eda_preprocessing.R"))
source(file.path(SCRIPT_DIR, "pca_analysis.R"))
source(file.path(SCRIPT_DIR, "supervised_learning.R"))
source(file.path(SCRIPT_DIR, "unsupervised_learning.R"))
source(file.path(SCRIPT_DIR, "extensive_eda.R"))

message("TITAN-R pipeline execution complete.")
