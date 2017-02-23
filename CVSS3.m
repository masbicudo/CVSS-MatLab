classdef CVSS3
    %CVSS3 Represents CVSS metrics for a vulnerability.
    %   Detailed explanation goes here
    
    % This code is implemented according to the specification
    % of the CVSS found at:
    %
    %   https://www.first.org/cvss/specification-document
    %
    
    properties (Constant)
        % lookup table defining all the parameter values
        lookup_table = struct( ...
             'AV', struct( 'N',0.85,  'A',0.62,  'L',0.55,  'P',0.20),                       ...
             'AC', struct( 'L',0.77,  'H',0.44),                                             ...
             'PR', struct('NC',0.85, 'NU',0.85, 'LC',0.68, 'LU',0.62, 'HC',0.50, 'HU',0.27), ...
             'UI', struct( 'N',0.85,  'R',0.62),                                             ...
              'C', struct( 'H',0.56,  'L',0.22,  'N',0.00),                                  ...
              'I', struct( 'H',0.56,  'L',0.22,  'N',0.00),                                  ...
              'A', struct( 'H',0.56,  'L',0.22,  'N',0.00),                                  ...
              'E', struct( 'X',1.00,  'N',1.00,  'H',1.00,  'F',0.97,  'P',0.94,  'U',0.91), ...
             'RL', struct( 'X',1.00,  'N',1.00,  'U',1.00,  'W',0.97,  'T',0.96,  'O',0.95), ...
             'RC', struct( 'X',1.00,  'N',1.00,  'C',1.00,  'R',0.96,  'U',0.92),            ...
                                                                                             ...
             'CR', struct( 'X',1.00,  'N',1.00,  'H',1.50,  'M',1.00,  'L',0.50),            ...
             'IR', struct( 'X',1.00,  'N',1.00,  'H',1.50,  'M',1.00,  'L',0.50),            ...
             'AR', struct( 'X',1.00,  'N',1.00,  'H',1.50,  'M',1.00,  'L',0.50),            ...
            'MAV', struct( 'N',0.85,  'A',0.62,  'L',0.55,  'P',0.20),                       ...
            'MAC', struct( 'L',0.77,  'H',0.44),                                             ...
            'MPR', struct('NC',0.85, 'NU',0.85, 'LC',0.68, 'LU',0.62, 'HC',0.50, 'HU',0.27), ...
            'MUI', struct( 'N',0.85,  'R',0.62),                                             ...
                                                                                             ...
             'MC', struct( 'H',0.56,  'L',0.22,  'N',0.00),                                  ...
             'MI', struct( 'H',0.56,  'L',0.22,  'N',0.00),                                  ...
             'MA', struct( 'H',0.56,  'L',0.22,  'N',0.00))
        
        map_modified_bases = struct( ...
            'MS' ,'S' , ...
            'MAV','AV', ...
            'MAC','AC', ...
            'MPR','PR', ...
            'MUI','UI', ...
            'MC' ,'C' , ...
            'MI' ,'I' , ...
            'MA' ,'A' )
        
        map_value_names = struct( ...
            'MS' , struct('X', 'Not Defined', 'U', 'Unchanged', 'C', 'Changed'),                                                ...
            'S'  , struct(                    'U', 'Unchanged', 'C', 'Changed'),                                                ...
            'MAV', struct('X', 'Not Defined', 'N', 'Network', 'A', 'Adjacent', 'L', 'Local', 'P', 'Physical'),                  ...
            'AV' , struct(                    'N', 'Network', 'A', 'Adjacent', 'L', 'Local', 'P', 'Physical'),                  ...
            'MAC', struct('X', 'Not Defined', 'L', 'Low', 'H', 'High'),                                                         ...
            'AC' , struct(                    'L', 'Low', 'H', 'High'),                                                         ...
            'MPR', struct('X', 'Not Defined', 'N', 'None', 'L', 'Low', 'H', 'High'),                                            ...
            'PR' , struct(                    'N', 'None', 'L', 'Low', 'H', 'High'),                                            ...
            'MUI', struct('X', 'Not Defined', 'N', 'None', 'R', 'Required'),                                                    ...
            'UI' , struct(                    'N', 'None', 'R', 'Required'),                                                    ...
            'MC' , struct('X', 'Not Defined', 'N', 'None', 'L', 'Low', 'H', 'High'),                                            ...
            'C'  , struct(                    'N', 'None', 'L', 'Low', 'H', 'High'),                                            ...
            'MI' , struct('X', 'Not Defined', 'N', 'None', 'L', 'Low', 'H', 'High'),                                            ...
            'I'  , struct(                    'N', 'None', 'L', 'Low', 'H', 'High'),                                            ...
            'MA' , struct('X', 'Not Defined', 'N', 'None', 'L', 'Low', 'H', 'High'),                                            ...
            'A'  , struct(                    'N', 'None', 'L', 'Low', 'H', 'High'),                                            ...
            'E'  , struct('X', 'Not Defined', 'H', 'High', 'F', 'Functional', 'P', 'Proof-of-Concept', 'U', 'Unproven'),        ...
            'RL' , struct('X', 'Not Defined', 'U', 'Unavailable', 'W', 'Workaround', 'T', 'Temporary Fix', 'O', 'Official Fix'),...
            'RC' , struct('X', 'Not Defined', 'C', 'Confirmed', 'R', 'Reasonable', 'U', 'Unknown'),                             ...
            'CR' , struct('X', 'Not Defined', 'H', 'High', 'M', 'Medium', 'L', 'Low'),                                          ...
            'IR' , struct('X', 'Not Defined', 'H', 'High', 'M', 'Medium', 'L', 'Low'),                                          ...
            'AR' , struct('X', 'Not Defined', 'H', 'High', 'M', 'Medium', 'L', 'Low')                                           )
    end
    properties (SetAccess = private)
        % Base
        AV      % Attack Vector         [N,A,L,P]
        AC      % Attack Complexity     [L,H]
        PR      % Privileges Required   [N,L,H]
        UI      % User Interaction      [N,R]
        S = 'U' % Scope                 [U,C]
        C       % Confidentiality       [H,L,N]
        I       % Integrity             [H,L,N]
        A       % Availability          [H,L,N]
        
        % Temporal
        E  = 'X' % Exploit Code Maturity [X,H,F,P,U]
        RL = 'X' % Remediation Level     [X,U,W,T,O]
        RC = 'X' % Report Confidence     [X,C,R,U]
        
        % Environmental
        CR = 'X' % Confidentiality Req. [X,H,M,L]
        IR = 'X' % Integrity Req.       [X,H,M,L]
        AR = 'X' % Availability Req.    [X,H,M,L]

        MAV = 'X' % Modified Attack Vector         [X,N,A,L,P]
        MAC = 'X' % Modified Attack Complexity     [X,L,H]
        MPR = 'X' % Modified Privileges Required   [X,N,L,H]
        MUI = 'X' % Modified User Interaction      [X,N,R]
        MS  = 'X' % Modified Scope                 [X,U,C]
        MC  = 'X' % Modified Confidentiality       [X,H,L,N]
        MI  = 'X' % Modified Integrity             [X,H,L,N]
        MA  = 'X' % Modified Availability          [X,H,L,N]
    end
    
    methods (Static)
        function [ M ] = Parse_Metrics_String( input_string )
        % Parses a CVSS string
        %   This function reads the CVSS string in input_string
        %   and generates a CVSS instance containig the numeric parameters.

            M = CVSS3.Parse_Custom_String(input_string, CVSS3.lookup_table);
        end
        
        function [ M ] = Parse_Custom_String( input_string, map )
        % Parses a CVSS string
        %   This function reads the CVSS string in input_string
        %   and generates a CVSS instance containig custom parameters.

            M = CVSS3.Parse_CVSS_String(input_string);

            % replacing string with numbers in the struct fields
            names = fieldnames(M);
            for i=1:size(names,1)
                k = names{i};
                if isfield(map, k)
                    tbl2 = map.(k);
                    switch k
                        case 'PR'
                            k2 = strcat(M.(k), M.S);
                        case 'MPR'
                            k2 = strcat(M.(k), M.MS);
                        otherwise
                            k2 = M.(k);
                    end
                    if isfield(tbl2, k2)
                        M.(k) = tbl2.(k2);
                    end
                end
            end
        end

        function [ M ] = Parse_CVSS_String( input_string )
        % Parses a CVSS string
        %   This function reads the CVSS string in input_string
        %   and generates a CVSS instance containig the string parameters.

            M = CVSS3();

            % converting the input_string to a struct
            input_string1 = strrep(input_string, ' ', '');
            pieces = strsplit(input_string1,'/');
            for i=1:size(pieces,2)
                kv = strsplit(pieces{i},':');
                if isprop(M, kv{1})
                    M.(upper(kv{1})) = upper(kv{2});
                end
            end

            % changing the 'modified' parameters if they have undefined values
            names = fieldnames(M);
            for i=1:size(names,1)
                k = names{i};
                if isfield(CVSS3.map_modified_bases, k)
                    kb = CVSS3.map_modified_bases.(k);
                    M.(k) = M.(kb);
                end
            end
        end
        
        function retval = roundup(n)
            retval = (ceil(10*n))/10;
        end
    end
    
    methods
        function retval = Base_Score(M)
            ISC = Impact_Subscore(M);
            
            if (ISC <= 0) 
                retval = 0;
            else
                Exploitability = Exploitability_Subscore(M);

                switch M.S
                    case 'U'
                        retval = CVSS3.roundup(min([ISC + Exploitability, 10]));
                    case 'C'
                        retval = CVSS3.roundup(min([1.08*(ISC + Exploitability), 10]));
                end
            end
        end

        function retval = Impact_Subscore(M)
            ISC_Base = 1 - ((1 - M.C)*(1 - M.I)*(1 - M.A));
            if (strcmp(M.S, 'U'))
                retval = 6.42*ISC_Base;
            else
                retval = 7.52*(ISC_Base - 0.029) - 3.25*(ISC_Base - 0.02)^15;
            end
        end
        
        function retval = Exploitability_Subscore(M)
            retval = 8.22 * M.AV * M.AC * M.PR * M.UI;
        end
        
        function retval = Temporal_Score(M)
            retval = ceil(10*(Base_Score(M) * M.E * M.RL * M.RC))/10;
        end
        
        function retval = Environmental_Score(M)
            switch M.MS
                case 'U'
                    adjustfactor=1.00;
                case 'C'
                    adjustfactor=1.08;
            end

            MISC = Modified_Impact_Subscore(M);
            if MISC < 0
                retval = 0;
            else
                retval = CVSS3.roundup( ...
                      CVSS3.roundup(min([adjustfactor * (MISC + Modified_Exploitability_Subscore(M)), 10])) ...
                    * M.E ...
                    * M.RL ...
                    * M.RC);
            end
        end
        
        function retval = Modified_Impact_Subscore(M)
            ISC_Modified = min([1 - (1 - M.MC *  M.CR)*(1- M.MI * M.IR)*(1 - M.MA * M.AR), 0.915]);
            switch M.MS
                case 'U'
                    retval = 6.42*ISC_Modified;
                case 'C'
                    retval = 7.52*(ISC_Modified - 0.029) - 3.25*(ISC_Modified - 0.02)^15;
            end
        end
        
        function retval = Modified_Exploitability_Subscore(M)
            retval = 8.22 * M.MAV * M.MAC * M.MPR * M.MUI;
        end
    end
end
