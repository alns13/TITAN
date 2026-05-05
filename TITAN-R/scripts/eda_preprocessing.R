if (!exists("DATA_DIR")) {
  if (exists("SCRIPT_DIR")) {
    source(file.path(SCRIPT_DIR, "paths.R"))
  } else {
    source(file.path(getwd(), "paths.R"))
  }
}

col_names <- c(
  "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
  "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
  "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
  "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
  "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
  "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
  "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
  "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
  "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
  "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack_type", "difficulty_level"
)

train_path <- file.path(DATA_DIR, "KDDTrain.csv")
test_path <- file.path(DATA_DIR, "KDDTest.csv")
if (!file.exists(train_path) || !file.exists(test_path)) {
  stop("Missing KDDTrain.csv or KDDTest.csv in ", DATA_DIR, ". Run setup_data.sh first.")
}

train_data <- read.csv(train_path, header = FALSE, col.names = col_names, stringsAsFactors = FALSE)
test_data <- read.csv(test_path, header = FALSE, col.names = col_names, stringsAsFactors = FALSE)

train_data$target <- ifelse(tolower(train_data$attack_type) == "normal", 0L, 1L)
test_data$target <- ifelse(tolower(test_data$attack_type) == "normal", 0L, 1L)

norm_attack <- function(a) {
  a <- tolower(trimws(as.character(a)))
  gsub("\\.+$", "", a)
}

map_attack_category <- function(attack_vec) {
  a <- norm_attack(attack_vec)
  out <- rep("Other", length(a))
  dos <- c(
    "back", "land", "neptune", "pod", "smurf", "teardrop", "apache2", "udpstorm",
    "processtable", "mailbomb", "worm"
  )
  probe <- c("satan", "ipsweep", "nmap", "portsweep", "mscan", "saint", "spy")
  r2l <- c(
    "guess_passwd", "warezmaster", "warezclient", "imap", "ftp_write", "multihop",
    "phf", "named", "sendmail", "snmpgetattack", "snmpguess", "xlock", "xsnoop",
    "httptunnel", "warezmaster", "warezclient"
  )
  u2r <- c("buffer_overflow", "loadmodule", "perl", "rootkit", "sqlattack", "xterm", "ps")
  out[a %in% dos] <- "DoS"
  out[a %in% probe] <- "Probe"
  out[a %in% r2l] <- "R2L"
  out[a %in% u2r] <- "U2R"
  out[a == "normal"] <- "Normal"
  factor(out, levels = c("Normal", "DoS", "Probe", "R2L", "U2R", "Other"))
}

train_data$attack_category <- map_attack_category(train_data$attack_type)
test_data$attack_category <- map_attack_category(test_data$attack_type)

cat_cols <- c("protocol_type", "service", "flag")
nm <- names(train_data)
num_from_raw <- nm[sapply(train_data, is.numeric) & nm != "target"]

train_cat <- train_data[, cat_cols, drop = FALSE]
test_cat <- test_data[, cat_cols, drop = FALSE]
for (v in cat_cols) {
  tab <- sort(table(as.character(train_cat[[v]])), decreasing = TRUE)
  modev <- names(tab)[1]
  tc <- as.character(test_cat[[v]])
  tc[!tc %in% names(tab)] <- modev
  test_cat[[v]] <- tc
}

for (v in cat_cols) {
  train_cat[[v]] <- factor(train_cat[[v]])
  test_cat[[v]] <- factor(as.character(test_cat[[v]]), levels = levels(train_cat[[v]]))
  if (any(is.na(test_cat[[v]]))) {
    mod <- names(which.max(table(train_cat[[v]])))
    test_cat[[v]][is.na(test_cat[[v]])] <- mod
  }
}

train_cat_df <- train_cat
test_cat_df <- test_cat
mm_tr <- model.matrix(~ 0 + protocol_type + service + flag, data = train_cat_df)
mm_te <- model.matrix(~ 0 + protocol_type + service + flag, data = test_cat_df)
train_d <- as.data.frame(mm_tr)
test_d <- as.data.frame(mm_te)
stopifnot(identical(names(train_d), names(test_d)))

train_num <- train_data[, num_from_raw, drop = FALSE]
test_num <- test_data[, num_from_raw, drop = FALSE]

X_train_full <- cbind(train_num, train_d)
X_test_full <- cbind(test_num, test_d)
stopifnot(identical(names(X_train_full), names(X_test_full)))

near_zero_var <- function(dat) {
  nms <- names(dat)
  drop <- setNames(logical(ncol(dat)), nms)
  for (j in seq_len(ncol(dat))) {
    x <- dat[[j]]
    if (!is.numeric(x)) {
      x <- suppressWarnings(as.numeric(x))
    }
    ok <- is.finite(x)
    if (sum(ok) < 2) {
      drop[j] <- TRUE
      next
    }
    x <- x[ok]
    vx <- stats::var(x)
    if (is.na(vx) || vx < 1e-12) {
      drop[j] <- TRUE
      next
    }
    tb <- sort(table(x), decreasing = TRUE)
    if (length(tb)) {
      freq_ratio <- as.numeric(tb[1]) / sum(tb)
      if (freq_ratio > 0.999) {
        drop[j] <- TRUE
      }
    }
  }
  drop
}

nzv <- near_zero_var(X_train_full)
if (any(nzv)) {
  message("Dropping near-zero-variance columns: ", paste(names(nzv)[nzv], collapse = ", "))
}
keep <- !nzv
X_train_full <- X_train_full[, keep, drop = FALSE]
X_test_full <- X_test_full[, keep, drop = FALSE]

center <- colMeans(X_train_full, na.rm = TRUE)
sc <- apply(X_train_full, 2, stats::sd, na.rm = TRUE)
sc[!is.finite(sc) | sc == 0] <- 1
train_X <- scale(X_train_full, center = center, scale = sc)
test_X <- scale(X_test_full, center = center, scale = sc)

train_final <- data.frame(train_X, target = train_data$target, attack_category = train_data$attack_category)
test_final <- data.frame(test_X, target = test_data$target, attack_category = test_data$attack_category)

saveRDS(train_final, file.path(DATA_DIR, "train_final.rds"))
saveRDS(test_final, file.path(DATA_DIR, "test_final.rds"))
saveRDS(
  list(
    encoding = "model.matrix_0_plus_categoricals",
    nzv_dropped = names(nzv)[nzv],
    kept_predictors = colnames(train_X),
    center = center,
    scale = sc
  ),
  file.path(DATA_DIR, "preprocess_meta.rds")
)

png(file.path(PLOT_DIR, "class_distribution.png"), width = 800, height = 600, res = 120)
barplot(
  table(train_data$target),
  names.arg = c("Normal (0)", "Malicious (1)"),
  main = "Training set: class distribution",
  ylab = "Count",
  col = c("steelblue", "coral")
)
dev.off()

p_cols <- colnames(train_X)
take <- p_cols[seq_len(min(40L, length(p_cols)))]
cmat <- cor(train_X[, take, drop = FALSE], use = "pairwise.complete.obs")
png(file.path(PLOT_DIR, "correlation_heatmap.png"), width = 1000, height = 800, res = 120)
heatmap(
  cmat,
  Rowv = NA,
  Colv = NA,
  symm = TRUE,
  main = "Correlation heatmap (subset of scaled predictors)",
  margins = c(10, 10)
)
dev.off()

message("EDA + preprocessing complete. train_final.rds / test_final.rds saved.")
