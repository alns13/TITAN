# Paths for TITAN-R. Prefer SCRIPT_DIR (set by full_pipeline.R) as .../scripts -> TITAN-R is parent.
infer_titan_r_root <- function() {
  args <- commandArgs(trailingOnly = FALSE)
  fn <- grep("^--file=", args, value = TRUE)
  if (length(fn)) {
    script_dir <- dirname(normalizePath(sub("^--file=", "", fn[1])))
    return(normalizePath(file.path(script_dir, "..")))
  }
  cwd <- normalizePath(getwd())
  if (file.exists(file.path(cwd, "data", "KDDTrain.csv"))) {
    return(cwd)
  }
  cand <- file.path(cwd, "TITAN-R")
  if (file.exists(file.path(cand, "data", "KDDTrain.csv"))) {
    return(normalizePath(cand))
  }
  if (basename(cwd) == "scripts") {
    return(normalizePath(file.path(cwd, "..")))
  }
  normalizePath(file.path(cwd, "TITAN-R"))
}

if (exists("SCRIPT_DIR")) {
  TITAN_R_ROOT <- normalizePath(file.path(SCRIPT_DIR, ".."))
} else {
  TITAN_R_ROOT <- infer_titan_r_root()
}

DATA_DIR <- file.path(TITAN_R_ROOT, "data")
PLOT_DIR <- file.path(TITAN_R_ROOT, "plots")

dir.create(DATA_DIR, showWarnings = FALSE, recursive = TRUE)
dir.create(PLOT_DIR, showWarnings = FALSE, recursive = TRUE)
