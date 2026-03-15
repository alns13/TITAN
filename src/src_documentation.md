The eda.py (exploratory data analysis) script is more or less just a quick test to see if the training data is roughly a 50/50 split between normal and malicious packets. To actually classify entries into the 2 categories, we just look at the value of their attack_type column. If it had an attack type listed like neptune, smurf, satan, etc. then it was deemed malicious, otherwise, normal.




The preprocess.py script cleans up the raw unformatted data into processed data that we can work with. Here's the 4 main things that the script does:

A. Data organization/processing. The biggest issue I found when I opened up the KDDTrain+.txt and KDDTest+.txt files was that they had no column names. It was just a text file values separated by commas. It has 43 variables/features that describe a network connection, like protocol, port, bytes, etc. Without the script, the AI would just be seeing "column 0, column 1, column 2 ... column 43" and it wouldn't know if a value of 100 meant 100 seconds or 100 failed logins. 

B. Classification mapping. The original dataset had many attack names like smurf, neptune, teardrop etc. which are all subtypes of DoS attacks. In our model, we don't really care too much about what kind of DoS attack we are receiving, but if it's malicious or not malicious. We assign Not Malicious to the value (0) and Malicious to the value (1). 
NOTE: We can scale the project and add features that differentiate between subtypes of certain attacks, but for now, keeping it at a binary result should be a good place to start. 

C. Turn columns with string values to integer values. There are some columns like protocol that cannot be quantified, because they are strings. To fix this, we just split the column protocol into 3 new columns for each value from the original column. So we are now left with Protocol_TCP, Protocol_UDP, and Protocol_ICMP. From here, we assign a value of 1 to Protocol_TCP if the packet is using TCP, and a value of 0 for the other 2. So yes, we originally had 43 features, and after processing, we now have 123. 
NOTE: because we did the normalization (Part D) after this step, we are not left with clean 0's and 1's. During the scaling, the 1's or "True" values all turned into some small positive decimal value, and all the 0's or "False" values turned into some small negative decimal value.

D. Normalization. In network traffic, src_bytes might be a value of 50,000 while num_failed_logins might only be 2 or 3. We obviously don't want the AI model to think that the src_bytes feature is more important than num_failed_logins, so we have to scale the numbers into a similar range first, before any training or testing can begin. 