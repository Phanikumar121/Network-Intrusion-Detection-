#Setting working directory
setwd("C:\\Users\\PHANI KUMAR\\Desktop\\Machine Learning Projects\\4. NETWORK-INTRUSION-DETECTION")

#Reading the data
train <- read.table("NSL_Dataset/Train.txt",sep = ",",header = F)
test <- read.table("NSL_Dataset/Test.txt",sep = ",",header = F)

#Loading required packages
library(ggplot2)
library(plotly)
library(caret)
library(randomForest)
library(e1071)
library(FSelector)
library(mlbench)
options(scipen = 999)

colnames_train <- c("Duration","Protocol_type","Service","Flag","Src_bytes","Dst_bytes","Land", 
                    "Wrong_fragment","Urgent","Hot","Num_failed_logins","Logged_in", "Num_compromised",
                    "Root_shell","Su_attempted","Num_root","Num_file_creations", "Num_shells",
                    "Num_access_files","Num_outbound_cmds","Is_host_login", "Is_guest_login","Count","Srv_count",
                    "Serror_rate", "Srv_serror_rate", "Rerror_rate","Srv_rerror_rate","Same_srv_rate",
                    "Diff_srv_rate", "Srv_diff_host_rate","Dst_host_count","Dst_host_srv_count",
                    "Dst_host_same_srv_rate", "Dst_host_diff_srv_rate","Dst_host_same_src_port_rate",
                    "Dst_host_srv_diff_host_rate","Dst_host_serror_rate","Dst_host_srv_serror_rate",
                    "Dst_host_rerror_rate","Dst_host_srv_rerror_rate","Attack", "Last_flag")

#Assigning column names
names(train) <- colnames_train
names(test) <- colnames_train

#Finding missing values
colSums(is.na(train))
colSums(is.na(test))

#There is no missing data in the columns

#Transforming the Attack column into 5 distinct types
#For train data
train$Attack <- as.character(train$Attack)
train$Attack[train$Attack == "ftp_write"] <- "R2L"
train$Attack[train$Attack == "guess_passwd"] <- "R2L"
train$Attack[train$Attack == "imap"] <- "R2L"
train$Attack[train$Attack == "multihop"] <- "R2L"
train$Attack[train$Attack == "phf"] <- "R2L"
train$Attack[train$Attack == "warezmaster"] <- "R2L"
train$Attack[train$Attack == "warezclient"] <- "R2L"
train$Attack[train$Attack == "spy"] <- "R2L"
train$Attack[train$Attack == "xlock"] <- "R2L"
train$Attack[train$Attack == "xsnoop"] <- "R2L"
train$Attack[train$Attack == "snmpguess"] <- "R2L"
train$Attack[train$Attack == "snmpgetattack"] <- "R2L"
train$Attack[train$Attack == "httptunnel"] <- "R2L"
train$Attack[train$Attack == "sendmail"] <- "R2L"
train$Attack[train$Attack == "named"] <- "R2L"


train$Attack[train$Attack == "land"] <- "DOS"
train$Attack[train$Attack == "back"] <- "DOS"
train$Attack[train$Attack == "neptune"] <- "DOS"
train$Attack[train$Attack == "pod"] <- "DOS"
train$Attack[train$Attack == "smurf"] <- "DOS"
train$Attack[train$Attack == "teardrop"] <- "DOS"
train$Attack[train$Attack == "apache2"] <- "DOS"
train$Attack[train$Attack == "udpstorm"] <- "DOS"
train$Attack[train$Attack == "processtable"] <- "DOS"
train$Attack[train$Attack == "worm"] <- "DOS"
train$Attack[train$Attack == "mailbomb"] <- "DOS"


train$Attack[train$Attack == "loadmodule"] <- "U2R"
train$Attack[train$Attack == "buffer_overflow"] <- "U2R"
train$Attack[train$Attack == "perl"] <- "U2R"
train$Attack[train$Attack == "rootkit"] <- "U2R"
train$Attack[train$Attack == "sqlattack"] <- "U2R"
train$Attack[train$Attack == "xterm"] <- "U2R"
train$Attack[train$Attack == "ps"] <- "U2R"


train$Attack[train$Attack == "nmap"] <- "Probe"
train$Attack[train$Attack == "ipsweep"] <- "Probe"
train$Attack[train$Attack == "portsweep"] <- "Probe"
train$Attack[train$Attack == "satan"] <- "Probe"
train$Attack[train$Attack == "mscan"] <- "Probe"
train$Attack[train$Attack == "saint"] <- "Probe"
train$Attack <- as.factor(train$Attack)

#For Test data

test$Attack <- as.character(test$Attack)
test$Attack[test$Attack == "ftp_write"] <- "R2L"
test$Attack[test$Attack == "guess_passwd"] <- "R2L"
test$Attack[test$Attack == "imap"] <- "R2L"
test$Attack[test$Attack == "multihop"] <- "R2L"
test$Attack[test$Attack == "phf"] <- "R2L"
test$Attack[test$Attack == "warezmaster"] <- "R2L"
test$Attack[test$Attack == "warezclient"] <- "R2L"
test$Attack[test$Attack == "spy"] <- "R2L"
test$Attack[test$Attack == "xlock"] <- "R2L"
test$Attack[test$Attack == "xsnoop"] <- "R2L"
test$Attack[test$Attack == "snmpguess"] <- "R2L"
test$Attack[test$Attack == "snmpgetattack"] <- "R2L"
test$Attack[test$Attack == "httptunnel"] <- "R2L"
test$Attack[test$Attack == "sendmail"] <- "R2L"
test$Attack[test$Attack == "named"] <- "R2L"


test$Attack[test$Attack == "land"] <- "DOS"
test$Attack[test$Attack == "back"] <- "DOS"
test$Attack[test$Attack == "neptune"] <- "DOS"
test$Attack[test$Attack == "pod"] <- "DOS"
test$Attack[test$Attack == "smurf"] <- "DOS"
test$Attack[test$Attack == "teardrop"] <- "DOS"
test$Attack[test$Attack == "apache2"] <- "DOS"
test$Attack[test$Attack == "udpstorm"] <- "DOS"
test$Attack[test$Attack == "processtable"] <- "DOS"
test$Attack[test$Attack == "worm"] <- "DOS"
test$Attack[test$Attack == "mailbomb"] <- "DOS"

test$Attack[test$Attack == "loadmodule"] <- "U2R"
test$Attack[test$Attack == "buffer_overflow"] <- "U2R"
test$Attack[test$Attack == "perl"] <- "U2R"
test$Attack[test$Attack == "rootkit"] <- "U2R"
test$Attack[test$Attack == "sqlattack"] <- "U2R"
test$Attack[test$Attack == "xterm"] <- "U2R"
test$Attack[test$Attack == "ps"] <- "U2R"


test$Attack[test$Attack == "nmap"] <- "Probe"
test$Attack[test$Attack == "ipsweep"] <- "Probe"
test$Attack[test$Attack == "portsweep"] <- "Probe"
test$Attack[test$Attack == "satan"] <- "Probe"
test$Attack[test$Attack == "mscan"] <- "Probe"
test$Attack[test$Attack == "saint"] <- "Probe"
test$Attack <- as.factor(test$Attack)

#Representing the attacks column graphically

bar_plot <- data.frame(table(train$Protocol_type, train$Attack))
bar_plot$Var1 <- NULL
colnames(bar_plot) <- c("sa","Attacks", "Frequency")

ggplot(bar_plot)+aes(x = bar_plot$Attacks,y = bar_plot$Frequency,fill = Attacks)+geom_bar(stat = "identity")+
  xlab("Attacks")+ylab("Frequency")+
  scale_fill_manual("legend",values = c("DOS" = "aquamarine","normal" ="chocolate1","Probe" = "cyan2","R2L" = "limegreen","U2R" = "gold"))

plotly::ggplotly(ggplot(bar_plot)+aes(x = bar_plot$Attacks,y = bar_plot$Frequency,fill = Attacks)+geom_bar(stat = "identity")+
                   xlab("Attacks")+ylab("Frequency")+
                   scale_fill_manual("legend",values = c("DOS" = "springgreen","normal" ="chocolate1","Probe" = "cyan2","R2L" = "limegreen","U2R" = "gold")))


#Variable selection with information.gain function
var_select <- information.gain(Attack~.,data = train)
print(var_select)
var_half <- cutoff.k(var_select, 25)
var_subset <- as.simple.formula(var_half, "Attack")
print(var_subset)

#I created a subset of the rows to make the analysis faster
train <- train[1:70000,]
train$Service= as.numeric(train$Service)
train$Flag= as.numeric(train$Flag)
train$Protocol_type= as.numeric(train$Protocol_type)

test$Service= as.numeric(test$Service)
test$Flag= as.numeric(test$Flag)
test$Protocol_type= as.numeric(test$Protocol_type)


#Selected vars into a data frame
selected_vars <- data.frame(Srv_count = train$Srv_count ,Same_srv_rate = train$Same_srv_rate,Count = train$Count, 
                    Flag = train$Flag,Dst_host_diff_srv_rate =  train$Dst_host_diff_srv_rate,
                    Dst_host_srv_diff_host_rate = train$Dst_host_srv_diff_host_rate , 
                    Dst_host_rerror_rate = train$ Dst_host_rerror_rate,Dst_bytes = train$Dst_bytes,
                    Src_bytes =  train$Src_bytes ,Dst_host_serror_rate =  train$Dst_host_serror_rate , 
                    Num_compromised = train$Num_compromised ,Dst_host_same_src_port_rate = train$Dst_host_same_src_port_rate,
                    Dst_host_count = train$Dst_host_count,Protocol_type =  train$Protocol_type,
                    Wrong_fragment = train$Wrong_fragment, Rerror_rate = train$Rerror_rate, 
                    Attack = train$Attack)

#Selecting vars in the test set
test_selected_vars <- data.frame(Srv_count = test$Srv_count ,Same_srv_rate = test$Same_srv_rate,Count = test$Count, 
                            Flag = test$Flag,Dst_host_diff_srv_rate =  test$Dst_host_diff_srv_rate,
                            Dst_host_srv_diff_host_rate = test$Dst_host_srv_diff_host_rate , 
                            Dst_host_rerror_rate = test$ Dst_host_rerror_rate,Dst_bytes = test$Dst_bytes,
                            Src_bytes =  test$Src_bytes ,Dst_host_serror_rate =  test$Dst_host_serror_rate , 
                            Num_compromised = test$Num_compromised ,Dst_host_same_src_port_rate = test$Dst_host_same_src_port_rate,
                            Dst_host_count = test$Dst_host_count,Protocol_type =  test$Protocol_type,
                            Wrong_fragment = test$Wrong_fragment, Rerror_rate = test$Rerror_rate, 
                            Attack = test$Attack)


#############################Model building#############################################

#Splitting the data to training and testing

set.seed(234)
training_split <- sample(1:nrow(selected_vars), size = floor(0.70 * nrow(selected_vars)))

training_sample <- selected_vars[training_split,]

testing_sample <- selected_vars[-training_split,]

#############################Random Forest Classification Model#############################################

#Network intrusion detection using Random Forest

randomforest_model <- randomForest(Attack~.,data = training_sample)

randomforest_pred <- predict(randomforest_model, testing_sample)

randomforest_accuracy <- confusionMatrix(randomforest_pred, testing_sample$Attack)

randomforest_accuracy$overall

###################################Naive Bayesian Classification Model#######################################

#Network intrusion detection using naive bayes classification

naivebayes_model <- naiveBayes(Attack ~ ., data = training_sample)

naivebayes_pred <- predict(naivebayes_model, testing_sample)

naivebayes_accuracy <- confusionMatrix(naivebayes_pred, testing_sample$Attack)

naivebayes_accuracy$overall

########################################SVM Classification Model###########################################

#Network intrusion detection using SVM classification

svm_model <-svm(Attack~., data = training_sample)

svm_pred <- predict(svm_model, testing_sample)

svm_accuracy <- confusionMatrix(svm_pred, testing_sample$Attack)

svm_accuracy$overall

##########################################End of classification###########################


#I would chose the model that is built on random forest because it gave me the best accuracy
#out of the three models . It gave me an accuracy of "0.9980476"

