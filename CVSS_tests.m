% CVE-2002-0392 'AV:N/AC:L/Au:N/C:N/I:N/A:C'
c = CVSS2.Parse_Metrics_String('AV:N/AC:L/Au:N/C:N/I:N/A:C');
c.Base_Score % 7.8

% Temporal worst case
ctbc = c.Fill_Parse('E:U/RL:OF/RC:UC');
stbc = ctbc.Temporal_Score;

% Temporal best case
ctwc = c.Fill_Parse('E:ND/RL:ND/RC:ND');
stwc = ctwc.Temporal_Score;

dt = stwc - stbc;

% Temporal worst case with RL=OF
ctbcRLOF = c.Fill_Parse('E:U/RL:OF/RC:UC');
stbcRLOF = ctbcRLOF.Temporal_Score;

ctwcRLOF = c.Fill_Parse('E:ND/RL:OF/RC:ND');
stwcRLOF = ctwcRLOF.Temporal_Score;

dtRLOF = stwcRLOF - stbcRLOF;

% Temporal worst case with RL=TF
ctbcRLTF = c.Fill_Parse('E:U/RL:TF/RC:UC');
stbcRLTF = ctbcRLTF.Temporal_Score;

ctwcRLTF = c.Fill_Parse('E:ND/RL:TF/RC:ND');
stwcRLTF = ctwcRLTF.Temporal_Score;

dtRLTF = stwcRLTF - stbcRLTF;

% Temporal worst case with RL=W
ctbcRLW = c.Fill_Parse('E:U/RL:W/RC:UC');
stbcRLW = ctbcRLW.Temporal_Score;

ctwcRLW = c.Fill_Parse('E:ND/RL:W/RC:ND');
stwcRLW = ctwcRLW.Temporal_Score;

dtRLW = stwcRLW - stbcRLW;

% Temporal worst case with RL=U
ctbcRLU = c.Fill_Parse('E:U/RL:U/RC:UC');
stbcRLU = ctbcRLU.Temporal_Score;

ctwcRLU = c.Fill_Parse('E:ND/RL:U/RC:ND');
stwcRLU = ctwcRLU.Temporal_Score;

dtRLU = stwcRLU - stbcRLU;



















c = c.Fill_Parse('CDP:H/TD:H/CR:M/IR:M/AR:H');
c.Environmental_Score % 9.2

% 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N/CR:N/IR:N/AR:N'
c = CVSS3.Parse_Metrics_String('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:N/CR:N/IR:N/AR:N');
c.Base_Score % 0.0?
c.Temporal_Score % 0.0?
c.Environmental_Score % 3.9?
