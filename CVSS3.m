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
        
        map_prop_names = struct( ...
             'AV', 'Attack Vector', ...
             'AC', 'Attack Complexity', ...
             'PR', 'Privileges Required', ...
             'UI', 'User Interaction', ...
              'S', 'Scope',
              'C', 'Confidentiality', ...
              'I', 'Integrity', ...
              'A', 'Availability', ...
            ...
              'E', 'Exploit Code Maturity', ...
             'RL', 'Remediation Level', ...
             'RC', 'Report Confidence', ...
            ...
             'CR', 'Confidentiality Req.', ...
             'IR', 'Integrity Req.', ...
             'AR', 'Availability Req.', ...
             'MS', 'Modified Scope', ...
            'MAV', 'Modified Attack Vector', ...
            'MAC', 'Modified Attack Complexity', ...
            'MPR', 'Modified Privileges Required', ...
            'MUI', 'Modified User Interaction', ...
             'MC', 'Modified Confidentiality', ...
             'MI', 'Modified Integrity', ...
             'MA', 'Modified Availability')
        
        map_prop_grups = struct( ...
             'AV', 'Base', ...
             'AC', 'Base', ...
             'PR', 'Base', ...
             'UI', 'Base', ...
              'S', 'Base',
              'C', 'Base', ...
              'I', 'Base', ...
              'A', 'Base', ...
            ...
              'E', 'Temporal', ...
             'RL', 'Temporal', ...
             'RC', 'Temporal', ...
            ...
             'CR', 'Environmental', ...
             'IR', 'Environmental', ...
             'AR', 'Environmental', ...
             'MS', 'Environmental', ...
            'MAV', 'Environmental', ...
            'MAC', 'Environmental', ...
            'MPR', 'Environmental', ...
            'MUI', 'Environmental', ...
             'MC', 'Environmental', ...
             'MI', 'Environmental', ...
             'MA', 'Environmental')

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
         
         prop_names = { 'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', 'E', 'RL', 'RC', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'  };
         group_names = { 'Base', 'Temporal', 'Environmental' };

         default_temporal = 'E:X/RL:X/RC:X';
         best_temporal = 'E:U/RL:O/RC:U';
         worst_temporal = 'E:H/RL:U/RC:C';
         
         default_environmental = 'CR:X/IR:X/AR:X/MS:X/MAV:X/MAC:X/MPR:X/MUI:X/MC:X/MI:X/MA:X';
         best_environmental = 'CR:L/IR:L/AR:L/MS:U/MAV:P/MAC:H/MPR:H/MUI:R/MC:N/MI:N/MA:N';
         worst_environmental = 'CR:H/IR:H/AR:H/MS:C/MAV:N/MAC:L/MPR:N/MUI:N/MC:H/MI:H/MA:H';
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
    properties
        RoundUnit = 0.1;
    end
    properties (Access = private)
    end
    
    methods (Static)
        function [ M ] = Parse_Metrics_String( input_string, varargin )
        % Parses a CVSS string
        %   This function reads the CVSS string in input_string
        %   and generates a CVSS instance containig the numeric parameters.
            opts = struct('IgnoreRequired', 0, 'Map', CVSS3.lookup_table);
            for a=1:2:nargin-2
                opts.(varargin{a}) = varargin{a+1};
            end

            M = CVSS3();
            M = CVSS3.Fill_CVSS_With_Parsed_String(M, input_string);
            M = CVSS3.Replace_Metrics( M, opts.Map );

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
            
            % checking required values
            if ~opts.IgnoreRequired
                if isempty(M.AV); error('CVSS3 parameter AV is required'); end;
                if isempty(M.AC); error('CVSS3 parameter AC is required'); end;
                if isempty(M.PR); error('CVSS3 parameter PR is required'); end;
                if isempty(M.UI); error('CVSS3 parameter UI is required'); end;
                if isempty(M.S ); error('CVSS3 parameter S is required') ; end;
                if isempty(M.C ); error('CVSS3 parameter C is required') ; end;
                if isempty(M.I ); error('CVSS3 parameter I is required') ; end;
                if isempty(M.A ); error('CVSS3 parameter A is required') ; end;
            end
        end

        function [ M ] = Parse_CVSS_String( input_string )
        % Parses a CVSS string
        %   This function reads the CVSS string in input_string
        %   and generates a CVSS instance containig the string parameters.

            M = CVSS3.Fill_CVSS_With_Parsed_String( CVSS3(), input_string );
        end
        
        function [ M ] = Fill_CVSS_With_Parsed_String( M, input_string )
        % Parses a CVSS string
        %   This function reads the CVSS string in input_string
        %   and fills a CVSS instance with the string parameters.

            % converting the input_string to a struct
            input_string1 = strrep(input_string, ' ', '');
            pieces = strsplit(input_string1,'/');
            for i=1:size(pieces,1)
                kv = strsplit(pieces{i},':');
                if CVSS3.isprop(kv{1})
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
        
        function [ M ] = Replace_Metrics( M, map )
            % replacing string with numbers in the struct fields
            if ischar(M.AV) && ~isempty(M.AV);  M.AV  = map.AV.(M.AV);   end;
            if ischar(M.AC) && ~isempty(M.AC);  M.AC  = map.AC.(M.AC);   end;
            if ischar(M.Au) && ~isempty(M.Au);  M.Au  = map.Au.(M.Au);   end;
            if ischar(M.C)  && ~isempty(M.C) ;  M.C   = map.C.(M.C);     end;
            if ischar(M.I)  && ~isempty(M.I) ;  M.I   = map.I.(M.I);     end;
            if ischar(M.A)  && ~isempty(M.A) ;  M.A   = map.A.(M.A);     end;

            % Temporal
            if ischar(M.E)  && ~isempty(M.E) ;  M.E   = map.E.(M.E);     end;
            if ischar(M.RL) && ~isempty(M.RL);  M.RL  = map.RL.(M.RL);   end;
            if ischar(M.RC) && ~isempty(M.RC);  M.RC  = map.RC.(M.RC);   end;

            % Environmental
            if ischar(M.CR) && ~isempty(M.CR);  M.CR  = map.CR.(M.CR);   end;
            if ischar(M.IR) && ~isempty(M.IR);  M.IR  = map.IR.(M.IR);   end;
            if ischar(M.AR) && ~isempty(M.AR);  M.AR  = map.AR.(M.AR);   end;

            if ischar(M.CDP)&& ~isempty(M.CDP); M.CDP = map.CDP.(M.CDP); end;
            if ischar(M.TD) && ~isempty(M.TD);  M.TD  = map.TD.(M.TD);   end;

            % CODE BEFORE OPTIMIZATION
            % names = fieldnames(M);
            % for i=1:size(names,1)
            %     k = names{i};
            %     if isfield(map, k) && ischar(M.(k))
            %         tbl2 = map.(k);
            %         k2 = M.(k);
            %         if isfield(tbl2, k2)
            %             M.(k) = tbl2.(k2);
            %         end
            %     end
            % end
        end
        
        function [ M ] = Revert_Metrics( M, map )
            names = fieldnames(map);
            for i=1:size(names,1)
                k = names{i};
                if isfield(map, k) && isnumeric(M.(k))
                    tbl2 = map.(k);
                    val = M.(k);
                    names2 = fieldnames(tbl2);
                    for j=1:size(names2,1)
                        k2 = names2{j};
                        if tbl2.(k2) == val
                            if strcmp(k, 'PR')
                                M.PR = k2(1);
                                M.S = k2(2);
                            elseif strcmp(k, 'MPR')
                                M.MPR = k2(1);
                                M.MS = k2(2);
                            else
                                M.(k) = k2;
                            end
                        end
                    end
                end
            end
        end

        function [ str ] = Convert_To_CvssString( M, map, varargin )
            opts = struct('IgnoreNotDefined', 0);
            for a=1:2:nargin-2
                opts.(varargin{a}) = varargin{a+1};
            end
            O = CVSS3.Revert_Metrics( M, map );
            str = '';
            names = fieldnames(M);
            for i=1:size(names,1)
                k = names{i};
                if isfield(map, k)
                    val = O.(k);
                    ignore = ischar(val) && strcmp(val, 'X') && opts.IgnoreNotDefined;
                    if ~ignore
                        if isempty(str)
                            str = [k ':' val];
                        else
                            str = [str '/' k ':' val];
                        end
                    end
                end
            end
        end

        function retval = round(u,n)
            retval = (round(1/u*n))*u; %(ceil(1/u*n))*u
        end
        
        function retval = isprop(propName)
            retval = any(strcmp(CVSS3.prop_names, propName));
        end
    end
    
    methods
        function [ O ] = WithDefaultTemporal(M)
            O = M.Fill_Parse( CVSS3.default_temporal );
        end
        function [ O ] = WithBestTemporal(M)
            O = M.Fill_Parse( CVSS3.best_temporal );
        end
        function [ O ] = WithWorstTemporal(M)
            O = M.Fill_Parse( CVSS3.worst_temporal );
        end
        function [ O ] = WithDefaultEnvironmental(M)
            O = M.Fill_Parse( CVSS3.default_environmental );
        end
        function [ O ] = WithBestEnvironmental(M)
            O = M.Fill_Parse( CVSS3.best_environmental );
        end
        function [ O ] = WithWorstEnvironmental(M)
            O = M.Fill_Parse( CVSS3.worst_environmental );
        end
        
        function retval = Base_Score(M)
            ISC = Impact_Subscore(M);
            
            if (ISC <= 0) 
                retval = 0;
            else
                Exploitability = Exploitability_Subscore(M);

                switch M.S
                    case 'U'
                        retval = CVSS3.round(M.RoundUnit, min([ISC + Exploitability, 10]));
                    case 'C'
                        retval = CVSS3.round(M.RoundUnit, min([1.08*(ISC + Exploitability), 10]));
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
                retval = CVSS3.round(M.RoundUnit,  ...
                      CVSS3.round(M.RoundUnit, min([adjustfactor * (MISC + Modified_Exploitability_Subscore(M)), 10])) ...
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
        
        function [ O ] = Fill_Parse( M, input_string )
        % Reparse returns a new CVSS3 object with additional metrics from
        % the given string.
            O = CVSS3.Fill_CVSS_With_Parsed_String( M, input_string );
            O = CVSS3.Replace_Metrics( O, CVSS3.lookup_table );
        end
        
        function [ O ] = With_Strings( M )
        % Converts this CVSS parameters to their equivalent string representations when possible.
            O = CVSS3.Revert_Metrics( M, CVSS3.lookup_table );
        end
        
        function [ str ] = ToString( M, varargin )
        % Converts this CVSS object to it's equivalent string representation.
            str = CVSS3.Convert_To_CvssString( M, CVSS3.lookup_table, varargin{:} );
        end
        
        function ForEach( M, f, varargin )
            names = CVSS3.prop_names;
            for i=1:size(names,2)
                k = names(i);
                k = k{1};
                val = M.(k);
                fullVal = val;
                if ischar(val)
                    fullVal = CVSS3.map_value_names.(k).(val);
                end
                data = struct( ...
                    'name', k, ...
                    'value', val, ...
                    'fullName', CVSS3.map_prop_names.(k), ...
                    'fullValue', fullVal );
                f(data, varargin{:});
            end
        end
    end
end
