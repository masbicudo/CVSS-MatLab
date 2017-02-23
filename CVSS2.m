classdef CVSS2
    %CVSS2 Represents CVSS 2 metrics for a vulnerability.
    
    % This code is implemented according to the specification
    % of the CVSS found at:
    %
    %   https://www.first.org/cvss/v2/guide
    %
    
    properties (Constant)
        % lookup table defining all the parameter values
        lookup_table = struct( ...
             'AV', struct( 'N',1.000,  'A',0.646,  'L',0.395),                               ...
             'AC', struct( 'L',0.710,  'M',0.610,  'H',0.350),                               ...
             'Au', struct( 'M',0.450,  'S',0.560,  'N',0.704),                               ...
              'C', struct( 'C',0.660,  'P',0.275,  'N',0.000),                               ...
              'I', struct( 'C',0.660,  'P',0.275,  'N',0.000),                               ...
              'A', struct( 'C',0.660,  'P',0.275,  'N',0.000),                               ...
                                                                                             ...
              'E', struct('ND',1.00,  'H',1.00,  'F',0.95,'POC',0.90,  'U',0.85),            ...
             'RL', struct('ND',1.00,  'U',1.00,  'W',0.95, 'TF',0.90, 'OF',0.87),            ...
             'RC', struct('ND',1.00,  'C',1.00, 'UR',0.95, 'UC',0.90),                       ...
                                                                                             ...
             'CR', struct('ND',1.00,  'H',1.51,  'M',1.00,  'L',0.50),                       ...
             'IR', struct('ND',1.00,  'H',1.51,  'M',1.00,  'L',0.50),                       ...
             'AR', struct('ND',1.00,  'H',1.51,  'M',1.00,  'L',0.50),                       ...
            'CDP', struct('ND',0.00,  'N',0.00,  'L',0.10, 'LM',0.30, 'MH',0.40,  'H',0.50), ...
             'TD', struct('ND',1.00,  'N',0.00,  'L',0.25,  'M',0.75,  'H',1.00))
        
        map_prop_names = struct( ...
            'AV', 'Attack Vector', ...
            'AC', 'Attack Complexity', ...
            'Au', 'Authentication', ...
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
            'CDP', 'Collateral Damage Potential', ...
            'TD', 'Target Distribution' ...
            )
        
        map_prop_grups = struct( ...
            'AV', 'Base', ...
            'AC', 'Base', ...
            'Au', 'Base', ...
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
            'CDP', 'Environmental', ...
            'TD', 'Environmental' ...
            )
        
        map_value_names = struct( ...
             'AV', struct( 'N', 'Network',  'A', 'Adjacent Network', 'L', 'Local'),                                                ...
             'AC', struct( 'H', 'High',     'M', 'Medium',  'L', 'Low'),                                                           ...
             'Au', struct( 'M', 'Multiple', 'S', 'Single',  'N', 'None'),                                                          ...
              'C', struct( 'C', 'Complete', 'P', 'Partial', 'N', 'None'),                                                          ...
              'I', struct( 'C', 'Complete', 'P', 'Partial', 'N', 'None'),                                                          ...
              'A', struct( 'C', 'Complete', 'P', 'Partial', 'N', 'None'),                                                          ...
                                                                                                                                   ...
              'E', struct('ND', 'Not Defined', 'H', 'High',        'F', 'Functional', 'POC', 'Proof-of-Concept', 'U', 'Unproven'), ...
             'RL', struct('ND', 'Not Defined', 'U', 'Unavailable', 'W', 'Workaround', 'TF', 'Temporary Fix', 'OF', 'Official Fix'), ...
             'RC', struct('ND', 'Not Defined', 'C', 'Confirmed',   'UR', 'Uncorroborated', 'UC', 'Unconfirmed'),                   ...
                                                                                                                                   ...
             'CR', struct('ND', 'Not Defined',              'H', 'High',  'M', 'Medium',                          'L', 'Low'),     ...
             'IR', struct('ND', 'Not Defined',              'H', 'High',  'M', 'Medium',                          'L', 'Low'),     ...
             'AR', struct('ND', 'Not Defined',              'H', 'High',  'M', 'Medium',                          'L', 'Low'),     ...
            'CDP', struct('ND', 'Not Defined', 'N', 'None', 'H', 'High', 'MH', 'Medium-High', 'LM', 'Low-Medium', 'L', 'Low'),     ...
             'TD', struct('ND', 'Not Defined', 'N', 'None', 'H', 'High',  'M', 'Medium',                          'L', 'Low'))
         
         prop_names = { 'AV', 'AC', 'Au', 'C', 'I', 'A', 'E', 'RL', 'RC', 'CR', 'IR', 'AR','CDP', 'TD' };
         group_names = { 'Base', 'Temporal', 'Environmental' };

         default_temporal = 'E:ND/RL:ND/RC:ND';
         best_temporal = 'E:U/RL:OF/RC:UC';
         worst_temporal = 'E:H/RL:U/RC:C';
         
         default_environmental = 'CR:ND/IR:ND/AR:ND/CDP:ND/TD:ND';
         best_environmental = 'CR:L/IR:L/AR:L/CDP:N/TD:N';
         worst_environmental = 'CR:H/IR:H/AR:H/CDP:H/TD:H';
    end
    properties (SetAccess = private)
        % Base
        AV      % Attack Vector         [N,A,L]
        AC      % Attack Complexity     [H,M,L]
        Au      % Authentication        [M,S,N]
        C       % Confidentiality       [N,P,C]
        I       % Integrity             [N,P,C]
        A       % Availability          [N,P,C]
        
        % Temporal
        E  = 'ND' % Exploit Code Maturity [U,POC,F,H,ND]
        RL = 'ND' % Remediation Level     [OF,TF,W,U,ND]
        RC = 'ND' % Report Confidence     [UC,UR,C,ND]
        
        % Environmental
        CR = 'ND' % Confidentiality Req. [L,M,H,ND]
        IR = 'ND' % Integrity Req.       [L,M,H,ND]
        AR = 'ND' % Availability Req.    [L,M,H,ND]

        CDP = 'ND' % Collateral Damage Potential [N,L,LM,MH,H,ND]
        TD  = 'ND' % Target Distribution         [N,L,M,H,ND]
    end
    properties
        RoundUnit = 0.1;
    end
    properties (Access = private)
    end
    
    methods (Static)
        function [ M ] = Parse_Metrics_String( input_string )
        % Parses a CVSS string
        %   This function reads the CVSS string in input_string
        %   and generates a CVSS instance containig the numeric parameters.

            M = CVSS2.Parse_Custom_String(input_string, CVSS2.lookup_table);
        end
        
        function [ M ] = Parse_Custom_String( input_string, map )
        % Parses a CVSS string
        %   This function reads the CVSS string in input_string
        %   and generates a CVSS instance containig custom parameters.

            M = CVSS2();
            M = CVSS2.Fill_CVSS_With_Parsed_String(M, input_string);
            M = CVSS2.Replace_Metrics( M, map );

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
            names = fieldnames(M);
            for i=1:size(names,1)
                k = names{i};
                if isfield(map, k) && isnumeric(M.(k))
                    tbl2 = map.(k);
                    val = M.(k);
                    names2 = fieldnames(tbl2);
                    for j=1:size(names2,1)
                        k2 = names2{j};
                        if tbl2.(k2) == val
                            M.(k) = k2;
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
            str = '';
            names = fieldnames(M);
            for i=1:size(names,1)
                k = names{i};
                if isfield(map, k)
                    val = M.(k);
                    if isnumeric(val)
                        tbl2 = map.(k);
                        names2 = fieldnames(tbl2);
                        for j=1:size(names2,1)
                            k2 = names2{j};
                            if tbl2.(k2) == val
                                val = k2;
                            end
                        end
                    end
                    ignore = ischar(val) && strcmp(val, 'ND') && opts.IgnoreNotDefined;
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

        function [ M ] = Parse_CVSS_String( input_string )
        % Parses a CVSS string
        %   This function reads the CVSS string in input_string
        %   and generates a CVSS instance containig the string parameters.

            M = CVSS2.Fill_CVSS_With_Parsed_String( CVSS2(), input_string );
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
                if CVSS2.isprop(kv{1})
                    M.(kv{1}) = upper(kv{2});
                end
            end
        end
        
        function retval = round_to_1_decimal(n)
            retval = (round(10*n))/10;
        end
        
        function retval = round(u,n)
            retval = (round(1/u*n))*u;
        end
        
        function retval = isprop(propName)
            retval = any(strcmp(CVSS2.prop_names, propName));
        end
    end
    
    methods
        function [ O ] = WithDefaultTemporal(M)
            O = M.Fill_Parse(CVSS2.default_temporal);
        end
        function [ O ] = WithBestTemporal(M)
            O = M.Fill_Parse(CVSS2.best_temporal);
        end
        function [ O ] = WithWorstTemporal(M)
            O = M.Fill_Parse(CVSS2.worst_temporal);
        end
        function [ O ] = WithDefaultEnvironmental(M)
            O = M.Fill_Parse(CVSS2.default_environmental);
        end
        function [ O ] = WithBestEnvironmental(M)
            O = M.Fill_Parse(CVSS2.best_environmental);
        end
        function [ O ] = WithWorstEnvironmental(M)
            O = M.Fill_Parse(CVSS2.worst_environmental);
        end
        
        function retval = Base_Score(M)
            % BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
            % f(impact) = 0 if Impact=0, 1.176 otherwise
            Impact = Impact_Subscore(M);
            retval = Internal_Base_Score(M, Impact);
        end

        function retval = Internal_Base_Score(M, Impact)
            % BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
            % f(impact) = 0 if Impact=0, 1.176 otherwise
            if (Impact == 0)
                retval = 0;
            else
                Exploitability = Exploitability_Subscore(M);
                retval = CVSS2.round(M.RoundUnit, (0.6*Impact + 0.4*Exploitability - 1.5)*1.176);
            end
        end
        
        function retval = Impact_Subscore(M)
            % Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
            retval = 10.41*(1 - ((1 - M.C)*(1 - M.I)*(1 - M.A)));
        end
        
        function retval = Exploitability_Subscore(M)
            % Exploitability = 20* AccessVector*AccessComplexity*Authentication
            retval = 20 * M.AV * M.AC * M.Au;
        end
        
        function retval = Temporal_Score(M)
            % TemporalScore = round_to_1_decimal(BaseScore*Exploitability*RemediationLevel*ReportConfidence)
            retval = CVSS2.round(M.RoundUnit, Base_Score(M) * M.E * M.RL * M.RC);
        end
        
        function retval = Environmental_Score(M)
            % EnvironmentalScore = round_to_1_decimal((AdjustedTemporal+
            % (10-AdjustedTemporal)*CollateralDamagePotential)*TargetDistribution)
            AdjustedTemporal = Adjusted_Temporal_Subscore(M);
            retval = CVSS2.round(M.RoundUnit, (AdjustedTemporal + (10 - AdjustedTemporal)*M.CDP)*M.TD);
        end
        
        function retval = Adjusted_Temporal_Subscore(M)
            % AdjustedTemporal = TemporalScore recomputed with the BaseScores Impact sub-equation replaced with the AdjustedImpact equation
            Impact = Adjusted_Impact_Subscore(M);
            retval = CVSS2.round(M.RoundUnit, Internal_Base_Score(M, Impact) * M.E * M.RL * M.RC);
        end
        
        function retval = Adjusted_Impact_Subscore(M)
            % AdjustedImpact = min(10,10.41*(1-(1-ConfImpact*ConfReq)*(1-IntegImpact*IntegReq)
            %                  *(1-AvailImpact*AvailReq)))
            retval = min([10, 10.41*(1 - (1 - M.C*M.CR)*(1 - M.I*M.IR)*(1 - M.A*M.AR))]);
        end
        
        function [ O ] = Fill_Parse( M, input_string )
        % Reparse returns a new CVSS2 object with additional metrics from
        % the given string.
            O = CVSS2.Fill_CVSS_With_Parsed_String( M, input_string );
            O = CVSS2.Replace_Metrics( O, CVSS2.lookup_table );
        end
        
        function [ O ] = With_Strings( M )
        % Converts this CVSS parameters to their equivalent string representations when possible.
            O = CVSS2.Revert_Metrics( M, CVSS2.lookup_table );
        end
        
        function [ str ] = ToString( M, varargin )
        % Converts this CVSS object to it's equivalent string representation.
            str = CVSS2.Convert_To_CvssString( M, CVSS2.lookup_table, varargin{:} );
        end
        
        function ForEach( M, f, varargin )
            names = CVSS2.prop_names;
            for i=1:size(names,2)
                k = names(i);
                k = k{1};
                val = M.(k);
                fullVal = val;
                if ischar(val)
                    fullVal = CVSS2.map_value_names.(k).(val);
                end
                data = struct( ...
                    'name', k, ...
                    'value', val, ...
                    'fullName', CVSS2.map_prop_names.(k), ...
                    'fullValue', fullVal );
                f(data, varargin{:});
            end
        end
    end
end
